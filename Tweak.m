/*
 * LINE 多账号容器 Dylib
 * 启动时显示账号选择页，每个账号使用独立沙盒 + Keychain 前缀
 *
 * 编译方式与 HookDylib 相同：
 *   clang -arch arm64 -shared -o LineAccount.dylib \
 *     -framework Foundation -framework UIKit -framework Security \
 *     -isysroot "$(xcrun --sdk iphoneos --show-sdk-path)" \
 *     -miphoneos-version-min=15.0 \
 *     Tweak.m
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <unistd.h>
#import <errno.h>
#import <stdlib.h>

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Wunused-function"

#define ACCOUNT_COUNT 4
#define SLOT_DIR_NAME @"LineAccountSlots"
#define SELECTED_SLOT_KEY @"LineAccount.SelectedSlot"

static NSInteger g_selectedSlot = -1;   // 0=临时, 1..4=账号
static BOOL g_pickerShown = NO;
static BOOL g_hooksInstalled = NO;
static BOOL g_needPicker = NO;      // 本次启动要先选账号
static BOOL g_blockLINEUI = NO;     // 挡住 LINE 原窗口，避免先闪登录页
static UIWindow *pickerWindow = nil;
static IMP orig_makeKeyAndVisible = NULL;
static IMP orig_didFinishLaunching = NULL;
static id g_deferredDelegate = nil;
static UIApplication *g_deferredApp = nil;
static NSDictionary *g_deferredOpts = nil;
static BOOL g_launchDeferred = NO;
static BOOL g_launchResumed = NO;

// Scene 生命周期也可能先于选择页初始化 LINE，必须一起暂缓
static IMP orig_sceneWillConnect = NULL;
static id g_deferredSceneTarget = nil;
static UIScene *g_deferredScene = nil;
static UISceneSession *g_deferredSceneSession = nil;
static id g_deferredSceneOpts = nil;
static BOOL g_sceneDeferred = NO;

static void showAccountPicker(void);
static void installHomeDirectoryHook(void);
static BOOL hooked_didFinishLaunching(id self, SEL _cmd, UIApplication *app, NSDictionary *opts);

#pragma mark - 路径工具

// 真实 App 沙盒 Home（永远不走 hook；启动时缓存一次）
static NSString *(*orig_NSHomeDirectory)(void) = NULL;
static NSString *g_realHomeCached = nil;

static NSString *realHomePath(void) {
    if (g_realHomeCached.length > 0) return g_realHomeCached;
    // 只用 dlsym 原指针，禁止 NSHomeDirectory()（若已被 hook 会递归崩）
    if (!orig_NSHomeDirectory) {
        orig_NSHomeDirectory = (NSString *(*)(void))dlsym(RTLD_DEFAULT, "NSHomeDirectory");
    }
    if (orig_NSHomeDirectory) {
        g_realHomeCached = [orig_NSHomeDirectory() copy];
    }
    if (g_realHomeCached.length == 0) {
        // 最后兜底：环境变量 HOME（iOS App 沙盒下通常可用）
        const char *env = getenv("HOME");
        if (env) g_realHomeCached = [[NSString alloc] initWithUTF8String:env];
    }
    return g_realHomeCached ?: @"/";
}

static NSString *slotsRootPath(void) {
    // 必须用真实沙盒 Home，不能走 hook 后的 NSHomeDirectory（否则会嵌套 LineAccountSlots）
    NSString *home = realHomePath();
    return [home stringByAppendingPathComponent:SLOT_DIR_NAME];
}

static NSString *slotHomePath(NSInteger slot) {
    // slot 0 = 选择页前临时容器；1..4 = 正式账号
    return [slotsRootPath() stringByAppendingPathComponent:
            [NSString stringWithFormat:@"account_%ld", (long)slot]];
}

static void mkdirp(NSString *path) {
    if (path.length == 0) return;
    const char *cpath = [path fileSystemRepresentation];
    if (!cpath) return;

    struct stat st;
    if (lstat(cpath, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return;
        // 关键点：中间某层若是「文件」而不是目录，后面所有 createDir 都会 ENOENT/FAIL
        // （PrivateStore/tN 全失败、而 com.naver.nelo 成功，就很像这条链上有文件挡路）
        unlink(cpath);
    }

    NSString *parent = [path stringByDeletingLastPathComponent];
    if (parent.length > 0 && ![parent isEqualToString:path] && ![parent isEqualToString:@"/"]) {
        mkdirp(parent);
    }
    if (mkdir(cpath, 0755) != 0 && errno != EEXIST) {
        // 再试一次：可能并发创建
        if (lstat(cpath, &st) == 0 && !S_ISDIR(st.st_mode)) {
            unlink(cpath);
        }
        mkdir(cpath, 0755);
    }
}

static void ensureSlotDirectories(NSInteger slot) {
    // 槽位内按 LINE 真实布局建目录；Talk DB 在 PrivateStore/P_<mid>/Messages
    NSArray *subs = @[
        @"Documents",
        @"Library/Preferences",
        @"Library/Caches",
        @"Library/Cookies",
        @"Library/Application Support",
        @"Library/Application Support/Messages",
        @"Library/Application Support/PrivateStore",
        @"Library/Application Support/PublicStore",
        @"tmp",
        @"AppGroup/group.com.linecorp.line",
        @"AppGroup/group.com.linecorp.Line.encrypted.app",
        @"AppGroup/group.share.com.linecorp.line",
        @"AppGroup/group.com.linecorp.Line.encrypted.share",
        @"AppGroup/group.com.linecorp.Line.encrypted.standard",
    ];
    NSString *root = slotHomePath(slot);
    mkdirp(root);
    for (NSString *sub in subs) {
        mkdirp([root stringByAppendingPathComponent:sub]);
    }
    NSDictionary *prot = @{NSFileProtectionKey: NSFileProtectionCompleteUntilFirstUserAuthentication};
    [[NSFileManager defaultManager] setAttributes:prot ofItemAtPath:root error:nil];
    NSLog(@"[LineAccount] slot=%ld root=%@", (long)slot, root);
}

// Talk DB 策略（已证实 symlink 易 ENOENT）：
// - 运行时始终用真实 Home/.../Messages + PrivateStore（不 remap）
// - 选账号时：换槽才切换；同槽重进只回写槽位、绝不 wipe 真实数据
// - 进后台 / 登录成功后再把真实数据持久化到当前槽
static void removePathPOSIX(NSString *path) {
    if (path.length == 0) return;
    const char *c = [path fileSystemRepresentation];
    if (!c) return;
    struct stat st;
    if (lstat(c, &st) != 0) return;
    if (S_ISLNK(st.st_mode) || S_ISREG(st.st_mode)) {
        unlink(c);
        return;
    }
    // 目录：用系统 rm - 在 ObjC 里用 FileManager 但路径含 SLOT 或真实 Messages 不 remap
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
}

static BOOL copyDirContents(NSString *src, NSString *dst) {
    NSFileManager *fm = [NSFileManager defaultManager];
    mkdirp(dst);
    NSError *err = nil;
    NSArray *items = [fm contentsOfDirectoryAtPath:src error:&err];
    if (!items) return NO;
    for (NSString *name in items) {
        NSString *s = [src stringByAppendingPathComponent:name];
        NSString *d = [dst stringByAppendingPathComponent:name];
        removePathPOSIX(d);
        NSError *e2 = nil;
        if (![fm copyItemAtPath:s toPath:d error:&e2]) {
            NSLog(@"[LineAccount] copy fail %@ -> %@ err=%@", s, d, e2);
            return NO;
        }
    }
    return YES;
}

// 换槽时清掉真实 Preferences 里除我们自己以外的条目（否则空槽会继承上一号登录态）
static void clearRealPreferencesForAccountSwitch(void) {
    NSString *prefs = [realHomePath() stringByAppendingPathComponent:@"Library/Preferences"];
    mkdirp(prefs);
    NSArray *items = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:prefs error:nil];
    for (NSString *name in items) {
        if ([name hasPrefix:@"LineAccount"]) continue;
        removePathPOSIX([prefs stringByAppendingPathComponent:name]);
    }
    [[NSUserDefaults standardUserDefaults] synchronize];
    [NSUserDefaults resetStandardUserDefaults];
}

static void clearRealDocuments(void) {
    NSString *docs = [realHomePath() stringByAppendingPathComponent:@"Documents"];
    NSArray *items = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:docs error:nil];
    for (NSString *name in items) {
        removePathPOSIX([docs stringByAppendingPathComponent:name]);
    }
    mkdirp(docs);
}

static void clearRealCookiesAndWebKit(void) {
    NSString *home = realHomePath();
    for (NSString *rel in @[@"Library/Cookies", @"Library/WebKit"]) {
        NSString *p = [home stringByAppendingPathComponent:rel];
        removePathPOSIX(p);
        mkdirp(p);
    }
}

static void replaceDirFromSrc(NSString *src, NSString *dst) {
    mkdirp([dst stringByDeletingLastPathComponent]);
    removePathPOSIX(dst);
    mkdirp(dst);
    NSArray *items = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:src error:nil];
    if (items.count == 0) return;
    copyDirContents(src, dst);
}

// 把真实运行态数据写回指定槽（登录态/聊天记录/附件持久化）
static void persistRealTalkDataToSlot(NSInteger slot) {
    if (slot < 1 || slot > ACCOUNT_COUNT) return;
    static NSLock *lock;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ lock = [[NSLock alloc] init]; });
    if (![lock tryLock]) {
        NSLog(@"[LineAccount] persist skip (busy) slot %ld", (long)slot);
        return;
    }

    ensureSlotDirectories(slot);

    NSString *realHome = realHomePath();
    NSString *slotHome = slotHomePath(slot);

    // 尽量把 CFPreferences 刷到磁盘再拷
    [[NSUserDefaults standardUserDefaults] synchronize];

    NSString *realAS = [realHome stringByAppendingPathComponent:@"Library/Application Support"];
    NSString *slotAS = [slotHome stringByAppendingPathComponent:@"Library/Application Support"];
    mkdirp(slotAS);
    for (NSString *name in @[@"Messages", @"PrivateStore", @"PublicStore"]) {
        NSString *src = [realAS stringByAppendingPathComponent:name];
        NSString *dst = [slotAS stringByAppendingPathComponent:name];
        const char *c = [src fileSystemRepresentation];
        struct stat st;
        if (!c || lstat(c, &st) != 0) continue;
        if (S_ISLNK(st.st_mode)) { unlink(c); continue; }
        if (!S_ISDIR(st.st_mode)) continue;
        replaceDirFromSrc(src, dst);
        NSLog(@"[LineAccount] persist AS/%@ -> slot %ld", name, (long)slot);
    }

    for (NSString *rel in @[@"Library/Preferences", @"Documents", @"Library/Cookies"]) {
        NSString *src = [realHome stringByAppendingPathComponent:rel];
        NSString *dst = [slotHome stringByAppendingPathComponent:rel];
        const char *c = [src fileSystemRepresentation];
        struct stat st;
        if (!c || lstat(c, &st) != 0) continue;
        if (S_ISREG(st.st_mode)) {
            mkdirp([dst stringByDeletingLastPathComponent]);
            removePathPOSIX(dst);
            NSError *e = nil;
            [[NSFileManager defaultManager] copyItemAtPath:src toPath:dst error:&e];
            continue;
        }
        if (!S_ISDIR(st.st_mode)) continue;
        replaceDirFromSrc(src, dst);
        NSLog(@"[LineAccount] persist %@ -> slot %ld", rel, (long)slot);
    }

    [[NSData data] writeToFile:[slotHome stringByAppendingPathComponent:@".used"] atomically:YES];
    [lock unlock];
}

static void loadTalkDataFromSlotToReal(NSInteger slot) {
    NSString *realHome = realHomePath();
    NSString *slotHome = slotHomePath(slot);
    NSString *realAS = [realHome stringByAppendingPathComponent:@"Library/Application Support"];
    NSString *slotAS = [slotHome stringByAppendingPathComponent:@"Library/Application Support"];
    mkdirp(realAS);

    // ★ 换槽先清登录态：空槽绝不能「保留真实 Preferences」，否则 1/2/3/4 都是同一个号
    clearRealPreferencesForAccountSwitch();
    clearRealDocuments();
    clearRealCookiesAndWebKit();

    for (NSString *name in @[@"Messages", @"PrivateStore", @"PublicStore"]) {
        NSString *src = [slotAS stringByAppendingPathComponent:name];
        NSString *dst = [realAS stringByAppendingPathComponent:name];
        removePathPOSIX(dst);
        mkdirp(dst);
        NSArray *items = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:src error:nil];
        if (items.count > 0) {
            copyDirContents(src, dst);
            NSLog(@"[LineAccount] load AS/%@ slot %ld -> real (%lu)", name, (long)slot, (unsigned long)items.count);
        } else {
            if ([name isEqualToString:@"PrivateStore"]) {
                mkdirp([dst stringByAppendingPathComponent:@"t0"]);
            }
            NSLog(@"[LineAccount] fresh AS/%@ for slot %ld", name, (long)slot);
        }
        NSDictionary *prot = @{NSFileProtectionKey: NSFileProtectionCompleteUntilFirstUserAuthentication};
        [[NSFileManager defaultManager] setAttributes:prot ofItemAtPath:dst error:nil];
    }

    // Preferences：从槽覆盖拷回（已清空真实侧 LINE 相关）
    NSString *srcPrefs = [slotHome stringByAppendingPathComponent:@"Library/Preferences"];
    NSString *dstPrefs = [realHome stringByAppendingPathComponent:@"Library/Preferences"];
    mkdirp(dstPrefs);
    NSArray *prefItems = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:srcPrefs error:nil];
    for (NSString *name in prefItems) {
        if ([name hasPrefix:@"LineAccount"]) continue;
        NSString *s = [srcPrefs stringByAppendingPathComponent:name];
        NSString *d = [dstPrefs stringByAppendingPathComponent:name];
        removePathPOSIX(d);
        NSError *e = nil;
        if (![[NSFileManager defaultManager] copyItemAtPath:s toPath:d error:&e]) {
            NSLog(@"[LineAccount] load Preferences fail %@ err=%@", name, e);
        }
    }
    [NSUserDefaults resetStandardUserDefaults];
    NSLog(@"[LineAccount] load Preferences slot %ld -> real (%lu)", (long)slot, (unsigned long)prefItems.count);

    for (NSString *rel in @[@"Documents", @"Library/Cookies"]) {
        NSString *src = [slotHome stringByAppendingPathComponent:rel];
        NSString *dst = [realHome stringByAppendingPathComponent:rel];
        NSArray *items = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:src error:nil];
        removePathPOSIX(dst);
        mkdirp(dst);
        if (items.count > 0) {
            copyDirContents(src, dst);
            NSLog(@"[LineAccount] load %@ slot %ld -> real (%lu)", rel, (long)slot, (unsigned long)items.count);
        } else {
            NSLog(@"[LineAccount] fresh %@ for slot %ld", rel, (long)slot);
        }
    }
}

static void syncTalkDBForSlot(NSInteger slot, NSInteger previousSlot) {
    if (slot < 1) return;

    NSString *realAS = [realHomePath() stringByAppendingPathComponent:@"Library/Application Support"];
    mkdirp(realAS);
    ensureSlotDirectories(slot);

    for (NSString *name in @[@"Messages", @"PrivateStore", @"PublicStore"]) {
        NSString *p = [realAS stringByAppendingPathComponent:name];
        const char *c = [p fileSystemRepresentation];
        struct stat st;
        if (c && lstat(c, &st) == 0 && S_ISLNK(st.st_mode)) {
            NSLog(@"[LineAccount] removing stale %@ symlink", name);
            unlink(c);
        }
        mkdirp(p);
    }
    // 真实 Talk DB：PrivateStore/P_<mid>/Messages/（Frida 已证实），不是只有 t0
    mkdirp([realAS stringByAppendingPathComponent:@"PrivateStore"]);

    // ★ 若 didFinishLaunching 未拦住，LINE/CoreData 已打开 sqlite —— 此时绝不能 wipe
    //   否则 → SQLite 6922 disk I/O error / abort（日志已证实）
    if (!g_launchDeferred) {
        NSLog(@"[LineAccount] WARNING launch NOT deferred — skip wipe/load, only ensure dirs + backup");
        persistRealTalkDataToSlot(slot);
        return;
    }

    if (previousSlot == slot) {
        persistRealTalkDataToSlot(slot);
        NSLog(@"[LineAccount] same slot %ld re-enter: kept real Talk DB, backed up to slot", (long)slot);
    } else {
        if (previousSlot >= 1 && previousSlot <= ACCOUNT_COUNT) {
            persistRealTalkDataToSlot(previousSlot);
        }
        loadTalkDataFromSlotToReal(slot);
    }

    // 探测 P_*/Messages/Line.sqlite
    NSString *ps = [realAS stringByAppendingPathComponent:@"PrivateStore"];
    NSArray *kids = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:ps error:nil];
    NSInteger pCount = 0;
    BOOL anyTalk = NO;
    for (NSString *k in kids) {
        if (![k hasPrefix:@"P_"] && ![k hasPrefix:@"p"]) continue;
        pCount++;
        NSString *talk = [[ps stringByAppendingPathComponent:k]
                          stringByAppendingPathComponent:@"Messages/Line.sqlite"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:talk]) anyTalk = YES;
    }
    NSLog(@"[LineAccount] talkdb ready PrivateStore children=%lu P_like=%ld hasTalkSqlite=%d t0=%d",
          (unsigned long)kids.count, (long)pCount, anyTalk,
          [[NSFileManager defaultManager] fileExistsAtPath:[ps stringByAppendingPathComponent:@"t0/Line.sqlite"]]);
}

static NSMutableDictionary *loadMeta(void); // forward — used by bindRealTalkDBDirToSlot

static void bindRealTalkDBDirToSlot(NSInteger slot) {
    NSInteger prev = 0;
    NSDictionary *meta = loadMeta();
    if (meta[@"selectedSlot"]) prev = [meta[@"selectedSlot"] integerValue];
    syncTalkDBForSlot(slot, prev);
}

#pragma mark - Talk DB / 账号事件（登录成功后失败会 unauthorize + exit(0)）

static IMP orig_accountAuthorized = NULL;
static IMP orig_accountUnauthorize = NULL;
static IMP orig_logPersistentStoreLoadError = NULL;

static void dumpTalkDBState(const char *tag) {
    if (g_selectedSlot < 1) return;
    NSString *realDb = [[realHomePath()
                         stringByAppendingPathComponent:@"Library/Application Support/Messages"]
                        stringByAppendingPathComponent:@"Line.sqlite"];
    NSString *slotDb = [[slotHomePath(g_selectedSlot)
                         stringByAppendingPathComponent:@"Library/Application Support/Messages"]
                        stringByAppendingPathComponent:@"Line.sqlite"];
    struct stat st;
    NSLog(@"[LineAccount][%s] slot=%ld realDb=%d (%@) slotDb=%d (%@)",
          tag, (long)g_selectedSlot,
          stat([realDb fileSystemRepresentation], &st) == 0, realDb,
          stat([slotDb fileSystemRepresentation], &st) == 0, slotDb);
}

static void hooked_accountEventAuthorizedAccount(id self, SEL _cmd) {
    // 隔离已由 NSHomeDirectory + 路径重定向完成：LINE 直接读写 account_N。
    // 不再做真实↔槽位互拷（那会用空的真实 Home 覆盖掉槽位里的真实数据）。
    dumpTalkDBState("beforeAuthorized");
    if (orig_accountAuthorized) {
        ((void (*)(id, SEL))orig_accountAuthorized)(self, _cmd);
    }
    dumpTalkDBState("afterAuthorized");
}

static void hooked_accountEventUnauthorizeAccountWithLevel(id self, SEL _cmd, NSInteger level) {
    NSLog(@"[LineAccount] UNAUTHORIZE level=%ld — will likely exit(0)", (long)level);
    dumpTalkDBState("unauthorize");
    if (orig_accountUnauthorize) {
        ((void (*)(id, SEL, NSInteger))orig_accountUnauthorize)(self, _cmd, level);
    }
}

static void hooked_logPersistentStoreLoadError(id self, SEL _cmd, id error) {
    NSLog(@"[LineAccount] TalkDB load error: %@", error);
    dumpTalkDBState("storeLoadError");
    if (orig_logPersistentStoreLoadError) {
        ((void (*)(id, SEL, id))orig_logPersistentStoreLoadError)(self, _cmd, error);
    }
}

static void installTalkDBAccountHooks(void) {
    static BOOL done = NO;
    if (done) return;

    Class mgr = NSClassFromString(@"LineCoreDataManager");
    if (mgr) {
        Method m = class_getInstanceMethod(mgr, @selector(accountEventAuthorizedAccount));
        if (m && !orig_accountAuthorized) {
            orig_accountAuthorized = method_setImplementation(m, (IMP)hooked_accountEventAuthorizedAccount);
            NSLog(@"[LineAccount] hooked accountEventAuthorizedAccount");
        }
        m = class_getInstanceMethod(mgr, @selector(accountEventUnauthorizeAccountWithLevel:));
        if (m && !orig_accountUnauthorize) {
            orig_accountUnauthorize = method_setImplementation(m, (IMP)hooked_accountEventUnauthorizeAccountWithLevel);
            NSLog(@"[LineAccount] hooked accountEventUnauthorizeAccountWithLevel:");
        }
    } else {
        NSLog(@"[LineAccount] LineCoreDataManager missing (talk hooks deferred)");
    }

    Class pc = NSClassFromString(@"LinePersistentContainer");
    if (pc) {
        Method m = class_getInstanceMethod(pc, @selector(logPersistentStoreLoadError:));
        if (m && !orig_logPersistentStoreLoadError) {
            orig_logPersistentStoreLoadError = method_setImplementation(m, (IMP)hooked_logPersistentStoreLoadError);
            NSLog(@"[LineAccount] hooked logPersistentStoreLoadError:");
            done = YES;
        }
    }

    // 类可能晚加载
    if (!orig_accountAuthorized || !orig_accountUnauthorize) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            Class m2 = NSClassFromString(@"LineCoreDataManager");
            if (!m2) return;
            if (!orig_accountAuthorized) {
                Method mm = class_getInstanceMethod(m2, @selector(accountEventAuthorizedAccount));
                if (mm) orig_accountAuthorized = method_setImplementation(mm, (IMP)hooked_accountEventAuthorizedAccount);
            }
            if (!orig_accountUnauthorize) {
                Method mm = class_getInstanceMethod(m2, @selector(accountEventUnauthorizeAccountWithLevel:));
                if (mm) orig_accountUnauthorize = method_setImplementation(mm, (IMP)hooked_accountEventUnauthorizeAccountWithLevel);
            }
        });
    } else {
        done = YES;
    }
}

static NSString *metaPlistPath(void) {
    mkdirp(slotsRootPath());
    return [slotsRootPath() stringByAppendingPathComponent:@"meta.plist"];
}

static NSMutableDictionary *loadMeta(void) {
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:metaPlistPath()];
    return d ? [d mutableCopy] : [NSMutableDictionary dictionary];
}

static void saveMeta(NSDictionary *meta) {
    [meta writeToFile:metaPlistPath() atomically:YES];
}

static NSString *slotKeyPrefix(NSInteger slot) {
    return [NSString stringWithFormat:@"line.slot.%ld.", (long)slot];
}

static BOOL pathNeedsRemap(NSString *path) {
    if (path.length == 0) return NO;
    if ([path containsString:SLOT_DIR_NAME]) return NO; // 槽位自身与 meta 不二次映射
    if (g_selectedSlot < 1) return NO;

    NSString *home = realHomePath();
    // 选中账号后：整个 App 沙盒 Home 下的路径都进 account_N（真正隔离）
    if (home.length > 0 && [path hasPrefix:home]) return YES;

    // 系统 Group Containers 也进槽位 AppGroup
    if ([path containsString:@"/Library/Group Containers/"]) return YES;

    return NO;
}

static NSString *remapPath(NSString *path) {
    if (g_selectedSlot < 1 || !pathNeedsRemap(path)) return path;

    NSString *home = realHomePath();
    NSString *slotHome = slotHomePath(g_selectedSlot);

    if ([path hasPrefix:home]) {
        NSString *rel = [path substringFromIndex:home.length];
        if ([rel hasPrefix:@"/"]) rel = [rel substringFromIndex:1];
        if ([rel hasPrefix:SLOT_DIR_NAME]) return path;
        return [slotHome stringByAppendingPathComponent:rel];
    }

    NSRange r = [path rangeOfString:@"/Library/Group Containers/"];
    if (r.location != NSNotFound) {
        NSString *after = [path substringFromIndex:r.location + r.length];
        return [[slotHome stringByAppendingPathComponent:@"AppGroup"]
                stringByAppendingPathComponent:after];
    }
    return path;
}

#pragma mark - Keychain 字典改写

static CFDictionaryRef rewriteKeychainQuery(CFDictionaryRef query, BOOL forWrite) {
    if (!query) return query;

    NSDictionary *orig = (__bridge NSDictionary *)query;
    NSMutableDictionary *m = [orig mutableCopy];

    // 重签 IPA 没有 LINE 原 keychain-access-groups，保留会 SecItem* → -34018
    [m removeObjectForKey:(__bridge id)kSecAttrAccessGroup];

    if (g_selectedSlot >= 1) {
        NSString *prefix = slotKeyPrefix(g_selectedSlot);

        id account = m[(__bridge id)kSecAttrAccount];
        if ([account isKindOfClass:[NSString class]]) {
            NSString *s = (NSString *)account;
            if (![s hasPrefix:prefix]) {
                m[(__bridge id)kSecAttrAccount] = [prefix stringByAppendingString:s];
            }
        } else if (forWrite) {
            m[(__bridge id)kSecAttrAccount] = [prefix stringByAppendingString:@"default"];
        }

        id service = m[(__bridge id)kSecAttrService];
        if ([service isKindOfClass:[NSString class]]) {
            NSString *s = (NSString *)service;
            if (![s hasPrefix:prefix]) {
                m[(__bridge id)kSecAttrService] = [prefix stringByAppendingString:s];
            }
        }
    }

    return CFBridgingRetain(m);
}

#pragma mark - 函数指针 Hook

typedef OSStatus (*SecItemAdd_t)(CFDictionaryRef, CFTypeRef *);
typedef OSStatus (*SecItemCopyMatching_t)(CFDictionaryRef, CFTypeRef *);
typedef OSStatus (*SecItemUpdate_t)(CFDictionaryRef, CFDictionaryRef);
typedef OSStatus (*SecItemDelete_t)(CFDictionaryRef);
typedef NSURL * (*ContainerURL_t)(id, SEL, NSString *);
typedef NSArray * (*SearchPath_t)(NSSearchPathDirectory, NSSearchPathDomainMask, BOOL);

static SecItemAdd_t orig_SecItemAdd = NULL;
static SecItemCopyMatching_t orig_SecItemCopyMatching = NULL;
static SecItemUpdate_t orig_SecItemUpdate = NULL;
static SecItemDelete_t orig_SecItemDelete = NULL;
static ContainerURL_t orig_containerURL = NULL;
static IMP orig_createDirectory = NULL;
static IMP orig_fileExists = NULL;
static IMP orig_contentsOfDirectory = NULL;
static IMP orig_removeItem = NULL;
static IMP orig_copyItem = NULL;
static IMP orig_moveItem = NULL;
static IMP orig_createFile = NULL;
static IMP orig_URLsForDirectory = NULL;

static OSStatus hooked_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    CFDictionaryRef q = rewriteKeychainQuery(attributes, YES);
    OSStatus st = orig_SecItemAdd(q, result);
    if (q != attributes) CFRelease(q);
    return st;
}

static OSStatus hooked_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    CFDictionaryRef q = rewriteKeychainQuery(query, NO);
    OSStatus st = orig_SecItemCopyMatching(q, result);
    if (q != query) CFRelease(q);
    return st;
}

static OSStatus hooked_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attrsToUpdate) {
    CFDictionaryRef q = rewriteKeychainQuery(query, NO);
    CFDictionaryRef a = rewriteKeychainQuery(attrsToUpdate, YES);
    OSStatus st = orig_SecItemUpdate(q, a);
    if (q != query) CFRelease(q);
    if (a != attrsToUpdate) CFRelease(a);
    return st;
}

static OSStatus hooked_SecItemDelete(CFDictionaryRef query) {
    CFDictionaryRef q = rewriteKeychainQuery(query, NO);
    OSStatus st = orig_SecItemDelete(q);
    if (q != query) CFRelease(q);
    return st;
}

static NSURL *hooked_containerURL(id self, SEL _cmd, NSString *groupId) {
    if (g_selectedSlot < 1) {
        if (orig_containerURL) {
            return orig_containerURL(self, _cmd, groupId);
        }
        return nil;
    }
    // 假 App Group 根 = 槽位 home，LINE 拼 PrivateStore/P_<mid>/… 会落在 account_N 下
    if (groupId.length > 0) {
        ensureSlotDirectories(g_selectedSlot);
        NSString *path = slotHomePath(g_selectedSlot);
        mkdirp([path stringByAppendingPathComponent:@"Library/Application Support/PrivateStore"]);
        NSLog(@"[LineAccount] containerURL(%@) -> slot %ld %@", groupId, (long)g_selectedSlot, path);
        return [NSURL fileURLWithPath:path isDirectory:YES];
    }
    if (orig_containerURL) {
        return orig_containerURL(self, _cmd, groupId);
    }
    return nil;
}

typedef BOOL (*CreateDirURL_t)(id, SEL, NSURL *, BOOL, NSDictionary *, NSError **);
static CreateDirURL_t orig_createDirectoryURL = NULL;

// 小整数绝不是合法 ObjC 对象（LINE 会把 storeType 枚举误当 NSURL 传入）
static BOOL isBogusObjPtr(const void *p) {
    return !p || ((uintptr_t)p) < 0x100000ULL;
}

static NSURL *urlFromMaybeBogus(NSURL *url) {
    uintptr_t v = (uintptr_t)(__bridge void *)url;
    if (v < 0x100000ULL) {
        NSInteger slot = g_selectedSlot >= 0 ? g_selectedSlot : 0;
        NSString *path = [[slotHomePath(slot)
                           stringByAppendingPathComponent:@"Library/Application Support/LineStores"]
                          stringByAppendingPathComponent:[NSString stringWithFormat:@"st%lu", (unsigned long)v]];
        mkdirp(path);
        NSLog(@"[LineAccount] coerce bogus URL %p -> %@", (void *)v, path);
        return [NSURL fileURLWithPath:path isDirectory:YES];
    }
    return url;
}

static NSString *pathFromMaybeBogus(NSString *path) {
    uintptr_t v = (uintptr_t)(__bridge void *)path;
    if (v == 0) return nil;
    if (v < 0x100000ULL) {
        NSInteger slot = g_selectedSlot >= 0 ? g_selectedSlot : 0;
        NSString *p = [[slotHomePath(slot)
                        stringByAppendingPathComponent:@"Library/Application Support/LineStores"]
                       stringByAppendingPathComponent:[NSString stringWithFormat:@"st%lu", (unsigned long)v]];
        mkdirp(p);
        NSLog(@"[LineAccount] coerce bogus path %p -> %@", (void *)v, p);
        return p;
    }
    return path;
}

// PrivateStore / 槽位路径：POSIX 建齐后一律视为成功
static BOOL ensurePrivateStoreDir(NSString *path) {
    if (path.length == 0) return NO;
    if (![path containsString:@"PrivateStore"] && ![path containsString:SLOT_DIR_NAME]) return NO;

    NSString *dir = path;
    if (path.pathExtension.length > 0) {
        dir = [path stringByDeletingLastPathComponent];
    }
    mkdirp(dir);
    const char *c = [dir fileSystemRepresentation];
    struct stat st;
    if (c && lstat(c, &st) == 0 && S_ISDIR(st.st_mode)) return YES;
    NSLog(@"[LineAccount] ensurePrivateStoreDir FAIL errno=%d %@", errno, dir);
    return NO;
}

static BOOL hooked_createDirectoryURL(id self, SEL _cmd, NSURL *url, BOOL intermediates,
                                      NSDictionary *attr, NSError **err) {
    if (isBogusObjPtr((__bridge void *)url)) {
        NSLog(@"[LineAccount] blocked createDirectoryAtURL:bogus %p", (__bridge void *)url);
        if (err) {
            *err = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileWriteInvalidFileNameError
                                   userInfo:@{NSLocalizedDescriptionKey: @"URL is bogus (blocked)"}];
        }
        return NO;
    }
    NSString *path = url.path;
    if (path.length == 0) {
        if (err) {
            *err = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileWriteInvalidFileNameError
                                   userInfo:@{NSLocalizedDescriptionKey: @"URL path empty"}];
        }
        return NO;
    }
    NSString *mapped = remapPath(path);
    if (ensurePrivateStoreDir(mapped)) return YES;
    if ([mapped containsString:SLOT_DIR_NAME] ||
        [mapped containsString:@"Application Support"] || [mapped containsString:@"Messages"]) {
        mkdirp(mapped);
        struct stat st;
        const char *c = [mapped fileSystemRepresentation];
        if (c && lstat(c, &st) == 0 && S_ISDIR(st.st_mode)) return YES;
    }
    if (mapped && ![mapped isEqualToString:path]) {
        url = [NSURL fileURLWithPath:mapped isDirectory:YES];
    }
    return orig_createDirectoryURL(self, _cmd, url, intermediates, attr, err);
}

static BOOL hooked_createDirectory(id self, SEL _cmd, NSString *path, BOOL intermediates, NSDictionary *attr, NSError **err) {
    path = pathFromMaybeBogus(path);
    if (path.length == 0) {
        if (err) {
            *err = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileWriteInvalidFileNameError
                                   userInfo:@{NSLocalizedDescriptionKey: @"path bogus/nil"}];
        }
        return NO;
    }
    NSString *mapped = remapPath(path);
    if (ensurePrivateStoreDir(mapped)) return YES;
    if ([mapped containsString:SLOT_DIR_NAME] ||
        [mapped containsString:@"Application Support"] || [mapped containsString:@"Messages"]) {
        mkdirp(mapped);
        struct stat st;
        const char *c = [mapped fileSystemRepresentation];
        if (c && lstat(c, &st) == 0 && S_ISDIR(st.st_mode)) return YES;
    }
    return ((BOOL(*)(id,SEL,NSString*,BOOL,NSDictionary*,NSError**))orig_createDirectory)
        (self, _cmd, mapped, intermediates, attr, err);
}

static BOOL hooked_fileExists(id self, SEL _cmd, NSString *path) {
    path = pathFromMaybeBogus(path);
    if (path.length == 0) return NO;
    return ((BOOL(*)(id,SEL,NSString*))orig_fileExists)(self, _cmd, remapPath(path));
}

static NSArray *hooked_contentsOfDirectory(id self, SEL _cmd, NSString *path, NSError **err) {
    path = pathFromMaybeBogus(path);
    if (path.length == 0) return @[];
    return ((NSArray*(*)(id,SEL,NSString*,NSError**))orig_contentsOfDirectory)
        (self, _cmd, remapPath(path), err);
}

static BOOL hooked_removeItem(id self, SEL _cmd, NSString *path, NSError **err) {
    path = pathFromMaybeBogus(path);
    if (path.length == 0) return NO;
    return ((BOOL(*)(id,SEL,NSString*,NSError**))orig_removeItem)(self, _cmd, remapPath(path), err);
}

static BOOL hooked_copyItem(id self, SEL _cmd, NSString *src, NSString *dst, NSError **err) {
    src = pathFromMaybeBogus(src);
    dst = pathFromMaybeBogus(dst);
    if (src.length == 0 || dst.length == 0) return NO;
    return ((BOOL(*)(id,SEL,NSString*,NSString*,NSError**))orig_copyItem)
        (self, _cmd, remapPath(src), remapPath(dst), err);
}

static BOOL hooked_moveItem(id self, SEL _cmd, NSString *src, NSString *dst, NSError **err) {
    src = pathFromMaybeBogus(src);
    dst = pathFromMaybeBogus(dst);
    if (src.length == 0 || dst.length == 0) return NO;
    return ((BOOL(*)(id,SEL,NSString*,NSString*,NSError**))orig_moveItem)
        (self, _cmd, remapPath(src), remapPath(dst), err);
}

static BOOL hooked_createFile(id self, SEL _cmd, NSString *path, NSData *data, NSDictionary *attr) {
    path = pathFromMaybeBogus(path);
    if (path.length == 0) return NO;
    NSString *mapped = remapPath(path);
    if ([mapped containsString:@"Line.sqlite"] || [mapped containsString:@"PrivateStore"] ||
        [mapped containsString:@"/Messages"] || [mapped containsString:@"talk.sqlite"]) {
        mkdirp([mapped stringByDeletingLastPathComponent]);
        NSLog(@"[LineAccount] createFile %@", mapped);
    }
    BOOL ok = ((BOOL(*)(id,SEL,NSString*,NSData*,NSDictionary*))orig_createFile)
        (self, _cmd, mapped, data, attr);
    if (!ok) NSLog(@"[LineAccount] createFile FAIL %@", mapped);
    return ok;
}

typedef BOOL (*ItemAtURL_t)(id, SEL, NSURL *, NSError **);
typedef BOOL (*CopyURL_t)(id, SEL, NSURL *, NSURL *, NSError **);
static ItemAtURL_t orig_removeItemURL = NULL;
static CopyURL_t orig_copyItemURL = NULL;
static CopyURL_t orig_moveItemURL = NULL;

static BOOL hooked_removeItemURL(id self, SEL _cmd, NSURL *url, NSError **err) {
    url = urlFromMaybeBogus(url);
    if (isBogusObjPtr((__bridge void *)url)) return NO;
    NSString *path = url.path;
    if (path.length == 0) return NO;
    NSString *mapped = remapPath(path);
    if (mapped && ![mapped isEqualToString:path]) {
        url = [NSURL fileURLWithPath:mapped isDirectory:NO];
    }
    return orig_removeItemURL(self, _cmd, url, err);
}

static BOOL hooked_copyItemURL(id self, SEL _cmd, NSURL *src, NSURL *dst, NSError **err) {
    src = urlFromMaybeBogus(src);
    dst = urlFromMaybeBogus(dst);
    if (isBogusObjPtr((__bridge void *)src) || isBogusObjPtr((__bridge void *)dst)) return NO;
    NSString *sp = remapPath(src.path);
    NSString *dp = remapPath(dst.path);
    return orig_copyItemURL(self, _cmd,
                            [NSURL fileURLWithPath:sp isDirectory:NO],
                            [NSURL fileURLWithPath:dp isDirectory:NO], err);
}

static BOOL hooked_moveItemURL(id self, SEL _cmd, NSURL *src, NSURL *dst, NSError **err) {
    src = urlFromMaybeBogus(src);
    dst = urlFromMaybeBogus(dst);
    if (isBogusObjPtr((__bridge void *)src) || isBogusObjPtr((__bridge void *)dst)) return NO;
    NSString *sp = remapPath(src.path);
    NSString *dp = remapPath(dst.path);
    return orig_moveItemURL(self, _cmd,
                            [NSURL fileURLWithPath:sp isDirectory:NO],
                            [NSURL fileURLWithPath:dp isDirectory:NO], err);
}

static NSArray *hooked_URLsForDirectory(id self, SEL _cmd, NSSearchPathDirectory dir, NSSearchPathDomainMask domain) {
    NSArray *urls = ((NSArray*(*)(id,SEL,NSSearchPathDirectory,NSSearchPathDomainMask))orig_URLsForDirectory)
        (self, _cmd, dir, domain);
    if (g_selectedSlot < 0) return urls;
    NSMutableArray *out = [NSMutableArray array];
    for (NSURL *u in urls) {
        NSString *p = remapPath(u.path);
        [out addObject:[NSURL fileURLWithPath:p isDirectory:YES]];
    }
    return out;
}

static void installLineFileManagerHooks(void);

static void installRuntimeHooks(void) {
    if (g_hooksInstalled) return;
    g_hooksInstalled = YES;

    // 与 imToken HookDylib 相同：ObjC method_setImplementation（非越狱可用）
    Class fm = [NSFileManager class];
    Method m;

    m = class_getInstanceMethod(fm, @selector(createDirectoryAtPath:withIntermediateDirectories:attributes:error:));
    if (m) orig_createDirectory = method_setImplementation(m, (IMP)hooked_createDirectory);

    m = class_getInstanceMethod(fm, @selector(createDirectoryAtURL:withIntermediateDirectories:attributes:error:));
    if (m) {
        orig_createDirectoryURL = (CreateDirURL_t)method_setImplementation(m, (IMP)hooked_createDirectoryURL);
    }

    m = class_getInstanceMethod(fm, @selector(fileExistsAtPath:));
    if (m) orig_fileExists = method_setImplementation(m, (IMP)hooked_fileExists);

    m = class_getInstanceMethod(fm, @selector(contentsOfDirectoryAtPath:error:));
    if (m) orig_contentsOfDirectory = method_setImplementation(m, (IMP)hooked_contentsOfDirectory);

    m = class_getInstanceMethod(fm, @selector(removeItemAtPath:error:));
    if (m) orig_removeItem = method_setImplementation(m, (IMP)hooked_removeItem);

    m = class_getInstanceMethod(fm, @selector(copyItemAtPath:toPath:error:));
    if (m) orig_copyItem = method_setImplementation(m, (IMP)hooked_copyItem);

    m = class_getInstanceMethod(fm, @selector(moveItemAtPath:toPath:error:));
    if (m) orig_moveItem = method_setImplementation(m, (IMP)hooked_moveItem);

    m = class_getInstanceMethod(fm, @selector(createFileAtPath:contents:attributes:));
    if (m) orig_createFile = method_setImplementation(m, (IMP)hooked_createFile);

    m = class_getInstanceMethod(fm, @selector(removeItemAtURL:error:));
    if (m) orig_removeItemURL = (ItemAtURL_t)method_setImplementation(m, (IMP)hooked_removeItemURL);

    m = class_getInstanceMethod(fm, @selector(copyItemAtURL:toURL:error:));
    if (m) orig_copyItemURL = (CopyURL_t)method_setImplementation(m, (IMP)hooked_copyItemURL);

    m = class_getInstanceMethod(fm, @selector(moveItemAtURL:toURL:error:));
    if (m) orig_moveItemURL = (CopyURL_t)method_setImplementation(m, (IMP)hooked_moveItemURL);

    m = class_getInstanceMethod(fm, @selector(URLsForDirectory:inDomains:));
    if (m) orig_URLsForDirectory = method_setImplementation(m, (IMP)hooked_URLsForDirectory);

    m = class_getInstanceMethod(fm, @selector(containerURLForSecurityApplicationGroupIdentifier:));
    if (m) {
        orig_containerURL = (ContainerURL_t)method_getImplementation(m);
        method_setImplementation(m, (IMP)hooked_containerURL);
    }

    // LineFileManager 在选账号前绝不能 hook：
    // privateFileStoresAreAccessible=YES + 合成 URL 会让 LINE 后续把 storeType 当对象用 → AV
    NSLog(@"[LineAccount] FileManager / AppGroup hooks installed (LFM deferred)");
}

#pragma mark - LineFileManager（重签无 App Group 时返回 nil 的根因）

static NSInteger activeSlotOrZero(void) {
    return g_selectedSlot >= 0 ? g_selectedSlot : 0;
}

// 绝不能对「可能是枚举整数」的指针发 ObjC 消息（@try 挡不住 SIGSEGV）
static NSString *tokenFromRaw(uintptr_t v) {
    if (v < 0x100000ULL) {
        return [NSString stringWithFormat:@"t%lu", (unsigned long)v];
    }
    return [NSString stringWithFormat:@"p%lx", (unsigned long)v];
}

static NSString *tokenFromId(id obj) {
    return tokenFromRaw((uintptr_t)(__bridge void *)obj);
}

static NSURL *remapFileURL(NSURL *url) {
    if (!url) return nil;
    NSString *path = url.path;
    if (path.length == 0) return url;
    NSString *mapped = remapPath(path);
    if (!mapped || [mapped isEqualToString:path]) return url;
    BOOL isDir = ([url.pathExtension length] == 0);
    if (isDir) mkdirp(mapped);
    else mkdirp([mapped stringByDeletingLastPathComponent]);
    return [NSURL fileURLWithPath:mapped isDirectory:isDir];
}

// 若仍走到合成 URL：一律进当前槽位（与 NSHomeDirectory/containerURL 一致）
static NSURL *syntheticPrivateStoreURL(NSString *token, NSString *sub) {
    NSInteger slot = activeSlotOrZero();
    ensureSlotDirectories(slot);
    if (token.length == 0) token = @"t0";
    if ([token hasPrefix:@"st"]) {
        token = [@"t" stringByAppendingString:[token substringFromIndex:2]];
    } else if (![token hasPrefix:@"t"] && ![token hasPrefix:@"p"] && ![token hasPrefix:@"P"]) {
        token = [NSString stringWithFormat:@"t%@", token];
    }
    NSString *base = (slot >= 1) ? slotHomePath(slot) : realHomePath();
    NSString *path = [[base
                       stringByAppendingPathComponent:@"Library/Application Support/PrivateStore"]
                      stringByAppendingPathComponent:token];
    if (sub.length > 0) {
        path = [path stringByAppendingPathComponent:sub];
    }
    mkdirp(path);
    NSLog(@"[LineAccount] PrivateStore -> %@", path);
    return [NSURL fileURLWithPath:path isDirectory:YES];
}

static NSURL *syntheticStoreURLTokens(NSString *a, NSString *b) {
    return syntheticPrivateStoreURL(a, b);
}

// + privateFileStoresAreAccessible —— 重签无 App Group 时原实现常为 NO；
// 强制 YES 会走 store 初始化。必须配合「先 orig 再 nil 兜底」，不能只给空目录。
static BOOL (*orig_privateFileStoresAreAccessible)(Class, SEL) = NULL;
static BOOL hooked_privateFileStoresAreAccessible(Class cls, SEL sel) {
    (void)cls; (void)sel;
    return YES;
}

// Frida 实测崩溃栈（点 loginButtonAction 后 Swift Task 里）:
//   objc_storeStrong ← LineAccount.dylib!hooked_fileURLForFileInStore
// 根因：参数写成 id 时 ARC 会 retain/storeStrong；LINE 常传枚举小整数 → 读 0x40 AV。
// 全部改成 uintptr_t，禁止 ARC 当对象处理。不调 orig。

static NSURL *(*orig_fileURLForStoreType)(Class, SEL, NSInteger) = NULL;
static NSURL *hooked_fileURLForStoreType(Class cls, SEL sel, NSInteger storeType) {
    (void)cls; (void)sel; (void)orig_fileURLForStoreType;
    NSURL *url = syntheticPrivateStoreURL([NSString stringWithFormat:@"t%ld", (long)storeType], nil);
    NSLog(@"[LineAccount] fileURLForStoreType:%ld -> %@", (long)storeType, url.path);
    return url;
}

static NSURL *(*orig_fileURLForStore)(Class, SEL, uintptr_t) = NULL;
static NSURL *hooked_fileURLForStore(Class cls, SEL sel, uintptr_t store) {
    (void)cls; (void)sel; (void)orig_fileURLForStore;
    return syntheticPrivateStoreURL(tokenFromRaw(store), nil);
}

static NSURL *(*orig_fileURLForStoreOfType)(Class, SEL, uintptr_t, NSInteger) = NULL;
static NSURL *hooked_fileURLForStoreOfType(Class cls, SEL sel, uintptr_t store, NSInteger type) {
    (void)cls; (void)sel; (void)orig_fileURLForStoreOfType;
    return syntheticPrivateStoreURL(tokenFromRaw(store),
                                   [NSString stringWithFormat:@"ty%ld", (long)type]);
}

static NSURL *(*orig_fileURLForStoreSubstore)(Class, SEL, uintptr_t, uintptr_t) = NULL;
static NSURL *hooked_fileURLForStoreSubstore(Class cls, SEL sel, uintptr_t store, uintptr_t sub) {
    (void)cls; (void)sel; (void)orig_fileURLForStoreSubstore;
    return syntheticPrivateStoreURL(tokenFromRaw(store), tokenFromRaw(sub));
}

static NSURL *(*orig_fileURLForFileInStore)(Class, SEL, uintptr_t, uintptr_t) = NULL;
static NSURL *hooked_fileURLForFileInStore(Class cls, SEL sel, uintptr_t name, uintptr_t store) {
    (void)cls; (void)sel; (void)orig_fileURLForFileInStore;
    NSURL *dir = syntheticPrivateStoreURL(tokenFromRaw(store), nil);
    NSString *path = [dir.path stringByAppendingPathComponent:tokenFromRaw(name)];
    mkdirp([path stringByDeletingLastPathComponent]);
    return [NSURL fileURLWithPath:path isDirectory:NO];
}

static NSURL *(*orig_fileURLForFileInStoreOfType)(Class, SEL, uintptr_t, uintptr_t, NSInteger) = NULL;
static NSURL *hooked_fileURLForFileInStoreOfType(Class cls, SEL sel, uintptr_t name, uintptr_t store, NSInteger type) {
    (void)cls; (void)sel; (void)orig_fileURLForFileInStoreOfType;
    NSURL *dir = syntheticPrivateStoreURL(tokenFromRaw(store),
                                         [NSString stringWithFormat:@"ty%ld", (long)type]);
    NSString *path = [dir.path stringByAppendingPathComponent:tokenFromRaw(name)];
    mkdirp([path stringByDeletingLastPathComponent]);
    return [NSURL fileURLWithPath:path isDirectory:NO];
}

static NSURL *(*orig_fileURLForFileInStoreSub)(Class, SEL, uintptr_t, uintptr_t, uintptr_t) = NULL;
static NSURL *hooked_fileURLForFileInStoreSub(Class cls, SEL sel, uintptr_t name, uintptr_t store, uintptr_t sub) {
    (void)cls; (void)sel; (void)orig_fileURLForFileInStoreSub;
    NSURL *dir = syntheticPrivateStoreURL(tokenFromRaw(store), tokenFromRaw(sub));
    NSString *path = [dir.path stringByAppendingPathComponent:tokenFromRaw(name)];
    mkdirp([path stringByDeletingLastPathComponent]);
    return [NSURL fileURLWithPath:path isDirectory:NO];
}

static void swizzleClassMethod(Class cls, SEL sel, IMP neu, void **origOut) {
    if (!cls || !neu) return;
    Method m = class_getClassMethod(cls, sel);
    if (!m) {
        NSLog(@"[LineAccount] missing class method: %@ %@", NSStringFromClass(cls), NSStringFromSelector(sel));
        return;
    }
    IMP old = method_setImplementation(m, neu);
    if (origOut) *origOut = (void *)old;
}

static void installLineFileManagerHooks(void) {
    Class cls = NSClassFromString(@"LineFileManager");
    if (!cls) {
        NSLog(@"[LineAccount] LineFileManager not found yet, will retry later");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            if (!NSClassFromString(@"LineFileManager")) {
                NSLog(@"[LineAccount] LineFileManager still missing");
                return;
            }
            installLineFileManagerHooks();
        });
        return;
    }

    static BOOL done = NO;
    if (done) return;
    done = YES;

    // ★ 只强制 accessible=YES。不要再伪造 fileURLForStore*：
    //   tokenFromRaw 把对象指针编成 p%lx，与真实 PrivateStore/P_<mid>/Messages 分叉，
    //   Frida 已证实崩溃库在 P_u3df.../Messages/Line.sqlite。
    swizzleClassMethod(cls, @selector(privateFileStoresAreAccessible),
                       (IMP)hooked_privateFileStoresAreAccessible,
                       (void **)&orig_privateFileStoresAreAccessible);

    NSLog(@"[LineAccount] LineFileManager hooks OK (accessible only; keep native P_<mid> paths)");
}

#pragma mark - fishhook Keychain（非越狱可用：只改 App 内镜像 + vm_protect）

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_CMD LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_CMD LC_SEGMENT
#endif

struct rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

static bool image_is_app_local(const struct mach_header *header) {
    Dl_info info;
    if (dladdr(header, &info) == 0 || !info.dli_fname) return false;
    const char *p = info.dli_fname;
    // 跳过系统库 / dyld shared cache，避免写只读页崩溃（非越狱必做）
    if (strncmp(p, "/System/", 8) == 0) return false;
    if (strncmp(p, "/usr/lib/", 9) == 0) return false;
    if (strncmp(p, "/Developer/", 11) == 0) return false;
    if (strstr(p, "LineAccount.dylib") != NULL) return false; // 不要 hook 自己
    // 只处理 App 包内镜像
    return strstr(p, ".app/") != NULL;
}

static bool safe_write_ptr(void **slot, void *value) {
    if (!slot) return false;
    size_t page = (size_t)getpagesize();
    uintptr_t addr = (uintptr_t)slot;
    uintptr_t page_start = addr & ~(page - 1);

    // iOS 上 __DATA_CONST 只读，必须先改权限（非越狱同样适用）
    kern_return_t kr = vm_protect(mach_task_self(),
                                  (vm_address_t)page_start,
                                  (vm_size_t)page,
                                  false,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        if (mprotect((void *)page_start, page, PROT_READ | PROT_WRITE) != 0) {
            NSLog(@"[LineAccount] vm_protect/mprotect failed for %p kr=%d", slot, kr);
            return false;
        }
    }

    *slot = value;

    vm_protect(mach_task_self(),
               (vm_address_t)page_start,
               (vm_size_t)page,
               false,
               VM_PROT_READ | VM_PROT_COPY);
    return true;
}

static int perform_rebinding_with_section(struct rebinding rebindings[], size_t count,
                                          section_t *sect, intptr_t slide, nlist_t *symtab,
                                          char *strtab, uint32_t *indirect_symtab) {
    uint32_t *indirect = indirect_symtab + sect->reserved1;
    void **bindings = (void **)((uintptr_t)slide + sect->addr);
    for (uint32_t i = 0; i < sect->size / sizeof(void *); i++) {
        uint32_t symIndex = indirect[i];
        if (symIndex == INDIRECT_SYMBOL_ABS || symIndex == INDIRECT_SYMBOL_LOCAL ||
            symIndex == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) {
            continue;
        }
        uint32_t strx = symtab[symIndex].n_un.n_strx;
        char *name = strtab + strx;
        if (name && name[0] == '_') {
            for (size_t j = 0; j < count; j++) {
                if (strcmp(&name[1], rebindings[j].name) == 0) {
                    if (rebindings[j].replaced != NULL &&
                        bindings[i] != rebindings[j].replacement) {
                        *(rebindings[j].replaced) = bindings[i];
                    }
                    if (!safe_write_ptr(&bindings[i], rebindings[j].replacement)) {
                        NSLog(@"[LineAccount] skip bind %s (page not writable)", rebindings[j].name);
                    }
                    break;
                }
            }
        }
    }
    return 0;
}

static void rebind_symbols_for_image(const struct mach_header *header, intptr_t slide,
                                     struct rebinding rebindings[], size_t count) {
    if (!image_is_app_local(header)) return;

    Dl_info info;
    if (dladdr(header, &info) == 0) return;
    NSLog(@"[LineAccount] rebind image: %s", info.dli_fname);

    segment_command_t *curSeg = NULL;
    segment_command_t *linkedit = NULL;
    struct symtab_command *symtabCmd = NULL;
    struct dysymtab_command *dysymCmd = NULL;

    uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
    for (uint32_t i = 0; i < header->ncmds; i++, cur += curSeg->cmdsize) {
        curSeg = (segment_command_t *)cur;
        if (curSeg->cmd == LC_SEGMENT_CMD) {
            if (strcmp(curSeg->segname, SEG_LINKEDIT) == 0) linkedit = curSeg;
        } else if (curSeg->cmd == LC_SYMTAB) {
            symtabCmd = (struct symtab_command *)curSeg;
        } else if (curSeg->cmd == LC_DYSYMTAB) {
            dysymCmd = (struct dysymtab_command *)curSeg;
        }
    }
    if (!symtabCmd || !dysymCmd || !linkedit || !dysymCmd->nindirectsyms) return;

    uintptr_t linkeditBase = (uintptr_t)slide + linkedit->vmaddr - linkedit->fileoff;
    nlist_t *symtab = (nlist_t *)(linkeditBase + symtabCmd->symoff);
    char *strtab = (char *)(linkeditBase + symtabCmd->stroff);
    uint32_t *indirect = (uint32_t *)(linkeditBase + dysymCmd->indirectsymoff);

    cur = (uintptr_t)header + sizeof(mach_header_t);
    for (uint32_t i = 0; i < header->ncmds; i++, cur += curSeg->cmdsize) {
        curSeg = (segment_command_t *)cur;
        if (curSeg->cmd == LC_SEGMENT_CMD) {
            section_t *sects = (section_t *)(cur + sizeof(segment_command_t));
            for (uint32_t j = 0; j < curSeg->nsects; j++) {
                section_t *sect = &sects[j];
                if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS ||
                    (sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
                    perform_rebinding_with_section(rebindings, count, sect, slide, symtab, strtab, indirect);
                }
            }
        }
    }
}

static struct rebinding *g_rebindings = NULL;
static size_t g_rebindings_count = 0;

static void _rebind_for_image(const struct mach_header *header, intptr_t slide) {
    if (g_rebindings_count == 0) return;
    rebind_symbols_for_image(header, slide, g_rebindings, g_rebindings_count);
}

static int rebind_symbols(struct rebinding rebindings[], size_t count) {
    size_t newCount = g_rebindings_count + count;
    struct rebinding *newArr = realloc(g_rebindings, sizeof(struct rebinding) * newCount);
    if (!newArr) return -1;
    g_rebindings = newArr;
    memcpy(g_rebindings + g_rebindings_count, rebindings, sizeof(struct rebinding) * count);
    g_rebindings_count = newCount;

    uint32_t imgCount = _dyld_image_count();
    for (uint32_t i = 0; i < imgCount; i++) {
        rebind_symbols_for_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i),
                                 rebindings, count);
    }
    _dyld_register_func_for_add_image(_rebind_for_image);
    return 0;
}

static void installKeychainHooks(void) {
    // 启动时缓存真实 Home（选账号前绝不把 NSHomeDirectory 指到槽位）
    (void)realHomePath();

    // 先保留原始指针，防止 rebind 失败时调用空指针
    if (!orig_SecItemAdd)
        orig_SecItemAdd = (SecItemAdd_t)dlsym(RTLD_DEFAULT, "SecItemAdd");
    if (!orig_SecItemCopyMatching)
        orig_SecItemCopyMatching = (SecItemCopyMatching_t)dlsym(RTLD_DEFAULT, "SecItemCopyMatching");
    if (!orig_SecItemUpdate)
        orig_SecItemUpdate = (SecItemUpdate_t)dlsym(RTLD_DEFAULT, "SecItemUpdate");
    if (!orig_SecItemDelete)
        orig_SecItemDelete = (SecItemDelete_t)dlsym(RTLD_DEFAULT, "SecItemDelete");

    struct rebinding rebs[4] = {
        {"SecItemAdd", (void *)hooked_SecItemAdd, (void **)&orig_SecItemAdd},
        {"SecItemCopyMatching", (void *)hooked_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching},
        {"SecItemUpdate", (void *)hooked_SecItemUpdate, (void **)&orig_SecItemUpdate},
        {"SecItemDelete", (void *)hooked_SecItemDelete, (void **)&orig_SecItemDelete},
    };
    rebind_symbols(rebs, 4);
    NSLog(@"[LineAccount] Keychain hooks installed (app-local + vm_protect, non-JB OK)");
}

// 选中账号后才 hook：让 CFPreferences / 大量 API 的 Home 落到 account_N
static NSString *hooked_NSHomeDirectory(void) {
    if (g_selectedSlot >= 1) {
        return slotHomePath(g_selectedSlot);
    }
    if (orig_NSHomeDirectory) return orig_NSHomeDirectory();
    return realHomePath();
}

static void installHomeDirectoryHook(void) {
    static BOOL done = NO;
    if (done) return;
    done = YES;
    (void)realHomePath();
    if (!orig_NSHomeDirectory) {
        orig_NSHomeDirectory = (NSString *(*)(void))dlsym(RTLD_DEFAULT, "NSHomeDirectory");
    }
    struct rebinding reb = {
        "NSHomeDirectory", (void *)hooked_NSHomeDirectory, (void **)&orig_NSHomeDirectory
    };
    rebind_symbols(&reb, 1);
    NSLog(@"[LineAccount] NSHomeDirectory -> slot when selected");
}

// 重签 IPA 缺 Intents/Siri entitlement 时，进聊天会走：
// +[INVocabulary sharedVocabulary] → dispatch_once 抛未捕获异常 → abort
// Frida 已证实栈在 Intents!sharedVocabulary，与 PrivateStore 贴纸 exists FAIL 无关
static id hooked_INVocabulary_sharedVocabulary(id self, SEL _cmd) {
    NSLog(@"[LineAccount] stub +[INVocabulary sharedVocabulary] (avoid Intents crash)");
    return nil;
}

static void installIntentsCrashGuards(void) {
    Class cls = NSClassFromString(@"INVocabulary");
    if (!cls) {
        NSLog(@"[LineAccount] INVocabulary class missing");
        return;
    }
    Method m = class_getClassMethod(cls, @selector(sharedVocabulary));
    if (!m) {
        NSLog(@"[LineAccount] INVocabulary sharedVocabulary missing");
        return;
    }
    method_setImplementation(m, (IMP)hooked_INVocabulary_sharedVocabulary);
    NSLog(@"[LineAccount] hooked +[INVocabulary sharedVocabulary] -> nil stub");
}

// 我们把 didFinishLaunching 延后到「选完账号」才执行，此时 iOS 认为启动早已完成，
// LINE 再调 BGTaskScheduler 注册后台任务就会抛：
//   NSInternalInconsistencyException: All launch handlers must be registered
//   before application finishes launching  → abort
// 后台任务对多账号核心功能不是必需的，直接把注册桩成 no-op（返回 NO，不抛异常）。
static BOOL hooked_BGTaskScheduler_register(id self, SEL _cmd, id identifier, id queue, id handler) {
    (void)self; (void)_cmd; (void)queue; (void)handler;
    NSLog(@"[LineAccount] stub BGTaskScheduler register '%@' (skip, avoid late-register crash)", identifier);
    return NO;
}

static void installBGTaskCrashGuards(void) {
    static BOOL done = NO;
    if (done) return;
    Class cls = NSClassFromString(@"BGTaskScheduler");
    if (!cls) {
        NSLog(@"[LineAccount] BGTaskScheduler class missing");
        return;
    }
    SEL sel = @selector(registerForTaskWithIdentifier:usingQueue:launchHandler:);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        NSLog(@"[LineAccount] BGTaskScheduler register selector missing");
        return;
    }
    method_setImplementation(m, (IMP)hooked_BGTaskScheduler_register);
    done = YES;
    NSLog(@"[LineAccount] hooked -[BGTaskScheduler register...] -> no-op (avoid late-register abort)");
}

#pragma mark - 账号选择 UI

static void enterAccountSlot(NSInteger slot);

@interface LineAccountPickerController : UIViewController
@end

@implementation LineAccountPickerController

- (BOOL)prefersStatusBarHidden { return YES; }

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithRed:0.06 green:0.72 blue:0.35 alpha:1.0];

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectZero];
    title.text = @"选择账号容器";
    title.textColor = UIColor.whiteColor;
    title.font = [UIFont boldSystemFontOfSize:28];
    title.textAlignment = NSTextAlignmentCenter;
    title.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:title];

    UILabel *sub = [[UILabel alloc] initWithFrame:CGRectZero];
    sub.text = @"点选后直接进入该账号；换号请完全退出 LINE 后重新打开";
    sub.textColor = [UIColor colorWithWhite:1 alpha:0.85];
    sub.font = [UIFont systemFontOfSize:14];
    sub.textAlignment = NSTextAlignmentCenter;
    sub.numberOfLines = 2;
    sub.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:sub];

    UIStackView *stack = [[UIStackView alloc] init];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 14;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:stack];

    for (NSInteger i = 1; i <= ACCOUNT_COUNT; i++) {
        UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
        NSString *flag = [slotHomePath(i) stringByAppendingPathComponent:@".used"];
        NSString *prefs = [slotHomePath(i) stringByAppendingPathComponent:@"Library/Preferences"];
        NSArray *prefItems = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:prefs error:nil];
        NSString *ps = [slotHomePath(i) stringByAppendingPathComponent:@"Library/Application Support/PrivateStore"];
        NSArray *psItems = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:ps error:nil];
        BOOL hasData = [[NSFileManager defaultManager] fileExistsAtPath:flag] ||
                       prefItems.count > 0 || psItems.count > 0;
        NSString *mark = hasData ? @"已有数据" : @"新建容器";
        [btn setTitle:[NSString stringWithFormat:@"账号 %ld  ·  %@", (long)i, mark]
             forState:UIControlStateNormal];
        btn.titleLabel.font = [UIFont boldSystemFontOfSize:18];
        [btn setTitleColor:[UIColor colorWithRed:0.06 green:0.45 blue:0.25 alpha:1.0]
                  forState:UIControlStateNormal];
        btn.backgroundColor = UIColor.whiteColor;
        btn.layer.cornerRadius = 12;
        btn.tag = i;
        btn.contentEdgeInsets = UIEdgeInsetsMake(16, 20, 16, 20);
        [btn addTarget:self action:@selector(onSelect:) forControlEvents:UIControlEventTouchUpInside];
        [stack addArrangedSubview:btn];
    }

    [NSLayoutConstraint activateConstraints:@[
        [title.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor constant:48],
        [title.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:24],
        [title.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-24],
        [sub.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:8],
        [sub.leadingAnchor constraintEqualToAnchor:title.leadingAnchor],
        [sub.trailingAnchor constraintEqualToAnchor:title.trailingAnchor],
        [stack.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor constant:20],
        [stack.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:32],
        [stack.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-32],
    ]];
}

- (void)onSelect:(UIButton *)sender {
    enterAccountSlot(sender.tag);
}

@end

#pragma mark - 无重启进入沙盒

static void hideLINEWindows(void);

static void dismissPicker(void) {
    g_blockLINEUI = NO;
    g_needPicker = NO;
    if (pickerWindow) {
        pickerWindow.hidden = YES;
        pickerWindow.rootViewController = nil;
        pickerWindow = nil;
    }

    // 只藏「高层 + 无 root」的空覆盖窗；不要动 level=0 的 HUD（登录流程可能用到）
    void (^fix)(UIWindow *) = ^(UIWindow *w) {
        if (!w) return;
        if (w.rootViewController) {
            w.hidden = NO;
            w.alpha = 1;
            w.userInteractionEnabled = YES;
            return;
        }
        if (w.windowLevel > UIWindowLevelNormal) {
            w.hidden = YES;
            w.alpha = 0;
            w.userInteractionEnabled = NO;
        }
    };

    for (UIWindow *w in UIApplication.sharedApplication.windows) {
        fix(w);
    }
    if (@available(iOS 13.0, *)) {
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
            if (![s isKindOfClass:[UIWindowScene class]]) continue;
            for (UIWindow *w in ((UIWindowScene *)s).windows) {
                fix(w);
            }
        }
    }
}

// 把带 rootVC 的主窗口设为 key；只藏高层空覆盖层
static void promoteMainWindowOnce(void) {
    __block UIWindow *best = nil;
    __block CGFloat bestArea = 0;

    void (^scan)(UIWindow *) = ^(UIWindow *w) {
        if (!w) return;
        if (!w.rootViewController) {
            if (w.windowLevel > UIWindowLevelNormal) {
                w.hidden = YES;
                w.alpha = 0;
                w.userInteractionEnabled = NO;
            }
            return;
        }
        w.hidden = NO;
        w.alpha = 1;
        w.userInteractionEnabled = YES;
        CGRect f = w.bounds;
        CGFloat area = f.size.width * f.size.height;
        if (w.windowLevel > UIWindowLevelNormal + 1) {
            area *= 0.1;
        }
        if (area > bestArea) {
            bestArea = area;
            best = w;
        }
    };

    for (UIWindow *w in UIApplication.sharedApplication.windows) {
        scan(w);
    }
    if (@available(iOS 13.0, *)) {
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
            if (![s isKindOfClass:[UIWindowScene class]]) continue;
            for (UIWindow *w in ((UIWindowScene *)s).windows) {
                scan(w);
            }
        }
    }

    if (!best) {
        NSLog(@"[LineAccount] no window with rootVC to promote");
        return;
    }
    if (best.isKeyWindow && !best.hidden && best.alpha > 0.99) {
        return; // 已是 key，别反复抢，否则打掉登录/注册弹层
    }
    if (orig_makeKeyAndVisible) {
        ((void(*)(id,SEL))orig_makeKeyAndVisible)(best, @selector(makeKeyAndVisible));
    } else {
        [best makeKeyAndVisible];
    }
    NSLog(@"[LineAccount] promoted main window %@ root=%@", best, best.rootViewController);
}

static void resumeLINELaunch(void) {
    if (g_launchResumed) return;
    g_launchResumed = YES;
    g_needPicker = NO;
    g_blockLINEUI = NO;

    dismissPicker();

    if (g_launchDeferred && orig_didFinishLaunching && g_deferredDelegate) {
        NSLog(@"[LineAccount] resume didFinishLaunching, slot=%ld", (long)g_selectedSlot);
        ((BOOL(*)(id,SEL,UIApplication*,NSDictionary*))orig_didFinishLaunching)(
            g_deferredDelegate,
            @selector(application:didFinishLaunchingWithOptions:),
            g_deferredApp,
            g_deferredOpts);
    } else {
        NSLog(@"[LineAccount] resume: launch was NOT deferred (deferred=%d orig=%p del=%p)",
              (int)g_launchDeferred, orig_didFinishLaunching, g_deferredDelegate);
    }
    g_deferredDelegate = nil;
    g_deferredApp = nil;
    g_deferredOpts = nil;
    g_launchDeferred = NO;

    if (g_sceneDeferred && orig_sceneWillConnect && g_deferredSceneTarget && g_deferredScene) {
        NSLog(@"[LineAccount] resume scene:willConnectToSession: slot=%ld", (long)g_selectedSlot);
        ((void(*)(id,SEL,UIScene*,UISceneSession*,id))orig_sceneWillConnect)(
            g_deferredSceneTarget,
            @selector(scene:willConnectToSession:options:),
            g_deferredScene,
            g_deferredSceneSession,
            g_deferredSceneOpts);
    }
    g_deferredSceneTarget = nil;
    g_deferredScene = nil;
    g_deferredSceneSession = nil;
    g_deferredSceneOpts = nil;
    g_sceneDeferred = NO;

    dismissPicker();
    promoteMainWindowOnce();

    // hook 保留到 promote 之后再卸，避免 promote 被挡；卸掉后登录弹窗不再被干扰
    if (orig_makeKeyAndVisible) {
        Method m = class_getInstanceMethod([UIWindow class], @selector(makeKeyAndVisible));
        if (m) method_setImplementation(m, orig_makeKeyAndVisible);
        orig_makeKeyAndVisible = NULL;
        NSLog(@"[LineAccount] UIWindow makeKeyAndVisible hook removed");
    }

    // LINE 异步建 Auth 窗：再 promote 一次即可（多次会抢登录弹层焦点）
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.35 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        promoteMainWindowOnce();
    });
}

static void enterAccountSlot(NSInteger slot) {
    if (slot < 1 || slot > ACCOUNT_COUNT) return;

    ensureSlotDirectories(slot);
    [[NSData data] writeToFile:[slotHomePath(slot) stringByAppendingPathComponent:@".used"] atomically:YES];

    // 仅用于 UI 上标记「已有数据」；不做「重启跳过选择页」用途
    NSMutableDictionary *meta = loadMeta();
    meta[@"selectedSlot"] = @(slot);
    saveMeta(meta);

    // ★ 选中后立刻在本进程激活该槽的隔离，再放行此前被拦住的 LINE 启动。
    //   关键前提：didFinishLaunching / scene:willConnect 之前已被拦下（未执行），
    //   所以此刻改 NSHomeDirectory + 路径重定向，LINE 会「全新」初始化到 account_N，
    //   不存在「已用真实 Home 初始化后再中途改」导致的崩溃。
    g_selectedSlot = slot;
    NSLog(@"[LineAccount] selected slot %ld — activate isolation & resume in-process", (long)slot);

    installHomeDirectoryHook();      // NSHomeDirectory() -> account_N
    installLineFileManagerHooks();   // PrivateStore 等落到 account_N
    installIntentsCrashGuards();     // 进聊天避免 INVocabulary abort
    installBGTaskCrashGuards();      // 放行后 LINE 注册后台任务会晚，桩掉避免 abort
    installTalkDBAccountHooks();

    resumeLINELaunch();              // 放行 didFinishLaunching / scene:willConnect
}

static void hideLINEWindows(void) {
    if (!g_blockLINEUI) return;
    for (UIWindow *w in UIApplication.sharedApplication.windows) {
        if (w == pickerWindow) continue;
        w.hidden = YES;
        w.alpha = 0;
        w.userInteractionEnabled = NO;
    }
    if (@available(iOS 13.0, *)) {
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
            if (![s isKindOfClass:[UIWindowScene class]]) continue;
            for (UIWindow *w in ((UIWindowScene *)s).windows) {
                if (w == pickerWindow) continue;
                w.hidden = YES;
                w.alpha = 0;
                w.userInteractionEnabled = NO;
            }
        }
    }
}

static void hooked_makeKeyAndVisible(UIWindow *self, SEL _cmd) {
    if (g_blockLINEUI && self != pickerWindow) {
        self.hidden = YES;
        self.alpha = 0;
        self.userInteractionEnabled = NO;
        if (pickerWindow) [pickerWindow makeKeyWindow];
        return;
    }
    ((void(*)(id,SEL))orig_makeKeyAndVisible)(self, _cmd);
}

static void installWindowBlockHook(void) {
    if (orig_makeKeyAndVisible) return;
    Method m = class_getInstanceMethod([UIWindow class], @selector(makeKeyAndVisible));
    if (m) {
        orig_makeKeyAndVisible = method_setImplementation(m, (IMP)hooked_makeKeyAndVisible);
        NSLog(@"[LineAccount] UIWindow makeKeyAndVisible hooked");
    }
}

static void showAccountPicker(void) {
    void (^present)(void) = ^{
        hideLINEWindows();

        UIWindowScene *scene = nil;
        if (@available(iOS 13.0, *)) {
            for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
                if (s.activationState == UISceneActivationStateForegroundActive &&
                    [s isKindOfClass:[UIWindowScene class]]) {
                    scene = (UIWindowScene *)s;
                    break;
                }
            }
            if (!scene) {
                for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
                    if ([s isKindOfClass:[UIWindowScene class]]) {
                        scene = (UIWindowScene *)s;
                        break;
                    }
                }
            }
        }

        if (!pickerWindow) {
            if (@available(iOS 13.0, *)) {
                if (scene) pickerWindow = [[UIWindow alloc] initWithWindowScene:scene];
            }
            if (!pickerWindow) {
                pickerWindow = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
            }
            pickerWindow.windowLevel = UIWindowLevelStatusBar + 200;
            pickerWindow.backgroundColor = [UIColor colorWithRed:0.06 green:0.72 blue:0.35 alpha:1.0];
            pickerWindow.rootViewController = [LineAccountPickerController new];
        }

        pickerWindow.frame = UIScreen.mainScreen.bounds;
        pickerWindow.hidden = NO;
        pickerWindow.alpha = 1;
        [pickerWindow makeKeyAndVisible];
        hideLINEWindows();
        g_pickerShown = YES;
        NSLog(@"[LineAccount] picker shown");
    };

    if ([NSThread isMainThread]) present();
    else dispatch_async(dispatch_get_main_queue(), present);

    if (g_blockLINEUI) {
        for (int i = 1; i <= 30; i++) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 0.05 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                if (!g_blockLINEUI) return;
                hideLINEWindows();
                if (pickerWindow) {
                    pickerWindow.hidden = NO;
                    pickerWindow.alpha = 1;
                    [pickerWindow makeKeyWindow];
                }
            });
        }
    }
}

static Method ownInstanceMethod(Class cls, SEL sel) {
    if (!cls || !sel) return NULL;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NULL;
    Class superCls = class_getSuperclass(cls);
    if (superCls) {
        Method ms = class_getInstanceMethod(superCls, sel);
        if (ms == m) return NULL; // 继承自父类，动它会搞崩系统
    }
    return m;
}

static void (*orig_setDelegate)(id, SEL, id) = NULL;

static void tryHookDidFinishOnDelegate(id del) {
    if (!del || orig_didFinishLaunching) return;
    Class cls = [del class];
    Method target = ownInstanceMethod(cls, @selector(application:didFinishLaunchingWithOptions:));
    if (!target) {
        NSLog(@"[LineAccount] delegate %@ has no OWN didFinishLaunching", cls);
        return;
    }
    orig_didFinishLaunching = method_setImplementation(target, (IMP)hooked_didFinishLaunching);
    NSLog(@"[LineAccount] hooked didFinishLaunching on %@", NSStringFromClass(cls));
}

static void hooked_setDelegate(id self, SEL _cmd, id del) {
    tryHookDidFinishOnDelegate(del);
    if (orig_setDelegate) {
        orig_setDelegate(self, _cmd, del);
    }
}

static BOOL hooked_didFinishLaunching(id self, SEL _cmd, UIApplication *app, NSDictionary *opts) {
    // 需要选账号：暂缓 LINE 真正启动，只出选择页
    if (g_needPicker && !g_launchResumed) {
        g_blockLINEUI = YES;
        g_launchDeferred = YES;
        g_deferredDelegate = self;
        g_deferredApp = app;
        g_deferredOpts = opts;
        showAccountPicker();
        NSLog(@"[LineAccount] didFinishLaunching deferred until account selected");
        return YES;
    }

    if (orig_didFinishLaunching) {
        return ((BOOL(*)(id,SEL,UIApplication*,NSDictionary*))orig_didFinishLaunching)(self, _cmd, app, opts);
    }
    return YES;
}

static void hooked_sceneWillConnect(id self, SEL _cmd, UIScene *scene, UISceneSession *session, id opts) {
    if (g_needPicker && !g_launchResumed) {
        g_blockLINEUI = YES;
        g_sceneDeferred = YES;
        g_deferredSceneTarget = self;
        g_deferredScene = scene;
        g_deferredSceneSession = session;
        g_deferredSceneOpts = opts;
        showAccountPicker();
        NSLog(@"[LineAccount] scene:willConnect deferred until account selected (%@)", [self class]);
        return;
    }
    if (orig_sceneWillConnect) {
        ((void(*)(id,SEL,UIScene*,UISceneSession*,id))orig_sceneWillConnect)(self, _cmd, scene, session, opts);
    }
}

static void hookSceneDelegates(void) {
    if (orig_sceneWillConnect) return;
    SEL sel = @selector(scene:willConnectToSession:options:);
    // 不再全表扫描：只碰名字像 LINE Scene 的类，且必须是本类自有方法
    unsigned int n = 0;
    Class *list = objc_copyClassList(&n);
    for (unsigned int i = 0; i < n; i++) {
        Class cls = list[i];
        NSString *name = NSStringFromClass(cls);
        if ([name hasPrefix:@"UI"] || [name hasPrefix:@"_"] || [name hasPrefix:@"NS"]) continue;
        if (![name containsString:@"Scene"] && ![name containsString:@"LINE"] && ![name containsString:@"Line"]) {
            continue;
        }
        Method m = ownInstanceMethod(cls, sel);
        if (!m) continue;
        orig_sceneWillConnect = method_setImplementation(m, (IMP)hooked_sceneWillConnect);
        NSLog(@"[LineAccount] hooked scene:willConnect on %@", name);
        break; // 只 hook 一个
    }
    if (list) free(list);
}

typedef int (*UIApplicationMain_t)(int, char **, NSString *, NSString *);
static UIApplicationMain_t orig_UIApplicationMain = NULL;

static int hooked_UIApplicationMain(int argc, char **argv, NSString *principal, NSString *delegateClassName) {
    NSLog(@"[LineAccount] UIApplicationMain principal=%@ delegate=%@", principal, delegateClassName);
    if ([delegateClassName isKindOfClass:[NSString class]] && delegateClassName.length > 0) {
        Class cls = NSClassFromString(delegateClassName);
        Method m = ownInstanceMethod(cls, @selector(application:didFinishLaunchingWithOptions:));
        if (m && !orig_didFinishLaunching) {
            orig_didFinishLaunching = method_setImplementation(m, (IMP)hooked_didFinishLaunching);
            NSLog(@"[LineAccount] hooked didFinish via UIApplicationMain: %@", delegateClassName);
        }
    }
    installWindowBlockHook();
    Method sd = class_getInstanceMethod([UIApplication class], @selector(setDelegate:));
    if (sd && !orig_setDelegate) {
        orig_setDelegate = (void (*)(id, SEL, id))method_setImplementation(sd, (IMP)hooked_setDelegate);
    }
    // Scene 延后到主线程再 hook，避免启动期扫类崩溃
    dispatch_async(dispatch_get_main_queue(), ^{
        hookSceneDelegates();
    });
    return orig_UIApplicationMain(argc, argv, principal, delegateClassName);
}

static void installUIApplicationMainHook(void) {
    static BOOL done = NO;
    if (done) return;
    done = YES;
    if (!orig_UIApplicationMain) {
        orig_UIApplicationMain = (UIApplicationMain_t)dlsym(RTLD_DEFAULT, "UIApplicationMain");
    }
    struct rebinding reb = {
        "UIApplicationMain", (void *)hooked_UIApplicationMain, (void **)&orig_UIApplicationMain
    };
    rebind_symbols(&reb, 1);
    NSLog(@"[LineAccount] UIApplicationMain hooked");
}

static void hookAppDelegate(void) {
    installWindowBlockHook();
    installUIApplicationMainHook();

    Method sd = class_getInstanceMethod([UIApplication class], @selector(setDelegate:));
    if (sd && !orig_setDelegate) {
        orig_setDelegate = (void (*)(id, SEL, id))method_setImplementation(sd, (IMP)hooked_setDelegate);
        NSLog(@"[LineAccount] hooked UIApplication setDelegate:");
    }
    tryHookDidFinishOnDelegate(UIApplication.sharedApplication.delegate);

    // 只试已知名字，禁止全表扫描 AppDelegate（易误 hook 父类方法 → 秒退）
    NSArray *names = @[@"AppDelegate", @"LINEAppDelegate", @"NLAppDelegate", @"LineAppDelegate"];
    for (NSString *name in names) {
        Class cls = NSClassFromString(name);
        Method m = ownInstanceMethod(cls, @selector(application:didFinishLaunchingWithOptions:));
        if (m && !orig_didFinishLaunching) {
            orig_didFinishLaunching = method_setImplementation(m, (IMP)hooked_didFinishLaunching);
            NSLog(@"[LineAccount] hooked %@", name);
        }
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        tryHookDidFinishOnDelegate(UIApplication.sharedApplication.delegate);
        hookSceneDelegates();
        if (g_needPicker && !g_launchResumed) showAccountPicker();
    });
}

__attribute__((constructor))
static void line_account_init(void) {
    (void)realHomePath();
    mkdirp(slotsRootPath());

    NSLog(@"[LineAccount] ========================================");
    NSLog(@"[LineAccount] multi-account: 每次冷启动都弹选择页 → 选中进入该账号");
    NSLog(@"[LineAccount] ========================================");

    // 每次冷启动都从头来：拦住 LINE、弹选择页；选中后当场激活隔离并放行。
    // 杀进程重开 = 新的冷启动 = 再次弹选择页。不记忆上次选择。
    g_needPicker = YES;
    g_blockLINEUI = YES;
    g_selectedSlot = -1;
    g_launchResumed = NO;
    g_launchDeferred = NO;
    g_sceneDeferred = NO;
    NSLog(@"[LineAccount] realHome=%@ slots=%@", realHomePath(), slotsRootPath());

    installRuntimeHooks();
    installKeychainHooks();
    installUIApplicationMainHook();
    installIntentsCrashGuards();
    installBGTaskCrashGuards();
    hookAppDelegate();

    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_needPicker && !g_launchResumed) showAccountPicker();
    });
}
