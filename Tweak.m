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
#import <dirent.h>
#import <errno.h>
#import <stdlib.h>
#import <stdio.h>

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Wunused-function"

#define ACCOUNT_COUNT 4
#define SLOT_DIR_NAME @"LineAccountSlots"
#define SELECTED_SLOT_KEY @"LineAccount.SelectedSlot"
#define LINE_BUILD_ID @"suiteName-redirect+eperm-childmove v8"

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
    // ★ 容器交换模型：槽备份区必须放在「被交换的目录之外」，否则交换 Application Support 时
    //   会把我们自己的槽存储也搬走。故放在 Library/ 下的独立目录（Library 可写、持久）。
    return [home stringByAppendingPathComponent:@"Library/LineSlots"];
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
        @"Library/AppGroup/group.com.linecorp.line",
        @"Library/AppGroup/group.com.linecorp.Line.encrypted.app",
        @"Library/AppGroup/group.share.com.linecorp.line",
        @"Library/AppGroup/group.com.linecorp.Line.encrypted.share",
        @"Library/AppGroup/group.com.linecorp.Line.encrypted.standard",
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
    // ★ 容器交换模型：不再重定向任何路径 —— LINE 直接用真实 Home，隔离由「选账号时搬数据」完成。
    //   保留此函数（及依赖它的文件 hook）只为兼容旧调用点，全部直通不改写。
    (void)path;
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
        return [[[slotHome stringByAppendingPathComponent:@"Library"]
                 stringByAppendingPathComponent:@"AppGroup"]
                stringByAppendingPathComponent:after];
    }
    return path;
}

#pragma mark - Keychain 字典改写

static CFDictionaryRef rewriteKeychainQuery(CFDictionaryRef query, BOOL forWrite) {
    (void)forWrite;
    if (!query) return query;

    NSDictionary *orig = (__bridge NSDictionary *)query;

    // ★ Keychain 隔离已改为「交换」模型：激活槽直接用 LINE 原生的无前缀凭证（与纯净重签版
    //   完全一致，不触发身份验证/恢复墙），切槽时再由 keychainSwap() 把整套凭证改名搬进/搬出
    //   line.slot.N.*。因此运行时这里不再按槽加前缀，只需去掉重签 IPA 没有的 access group
    //   （保留会导致 SecItem* → errSecMissingEntitlement -34018）。
    if (!orig[(__bridge id)kSecAttrAccessGroup]) return query;  // 无 agrp → 原样直通，省一次拷贝

    NSMutableDictionary *m = [orig mutableCopy];
    [m removeObjectForKey:(__bridge id)kSecAttrAccessGroup];
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
    // ★ 容器交换模型：App Group 真实容器在 /var/.../Shared/ 下，是所有槽共享的，且不在 Home 内、
    //   交换搬不到。故把它重定向到 Home 内的固定子目录 AppGroup/<groupId>，再把整个 AppGroup
    //   纳入交换集 —— 这样 App Group 数据也随账号隔离。
    if (groupId.length == 0) {
        return orig_containerURL ? orig_containerURL(self, _cmd, groupId) : nil;
    }
    // ★ 必须放在 Library/ 下：容器根目录 <UUID>/ 禁止新建顶层目录(EPERM)，
    //   否则 <UUID>/AppGroup 建不出来 → 其下所有 mkdir ENOENT → MessageExt CoreData 崩。
    NSString *path = [[[realHomePath() stringByAppendingPathComponent:@"Library"]
                       stringByAppendingPathComponent:@"AppGroup"]
                      stringByAppendingPathComponent:groupId];
    mkdirp(path);
    // ★ iOS 真实 App Group 容器由系统预建了 Library/Caches 等骨架目录。重定向到 Home 内后
    //   必须自己补齐，否则 LINE（如 MessageExtCoreDataManager）往 Library/Caches/... 建 sqlite 时
    //   父目录缺失 → mkdir ENOENT → CoreData "Error validating url for store" → 抛异常 abort。
    static NSArray *skel;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        skel = @[@"Library",
                 @"Library/Caches",
                 @"Library/Caches/PrivateStore",
                 @"Library/Preferences",
                 @"Library/Application Support",
                 @"Library/Application Support/PrivateStore",
                 @"Library/Application Support/PublicStore",
                 @"Documents",
                 @"tmp"];
    });
    for (NSString *sub in skel) {
        mkdirp([path stringByAppendingPathComponent:sub]);
    }
    return [NSURL fileURLWithPath:path isDirectory:YES];
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

#pragma mark - NSData / NSDictionary 文件 I/O 重定向（堵 backupUserDefaults.dict 等共享泄漏）

// 这些读写文件方法在 NSData / NSDictionary 上，不在 NSFileManager 上，之前完全没拦。
// LINE 的加密 UserDefaults 备份（backupUserDefaults.dict / encryptedBackupUserDefaults.dict）
// 就是用 NSDictionary/NSData writeToFile: 直接写到共享真实 home，导致 4 槽共用登录态/身份。
// 在最终 I/O 层按最终路径 remap：无论路径怎么拼出来的（哪怕选账号前就缓存成真实 home），
// 只要落点在真实 home 一律拉回当前槽 —— 这是最彻底的兜底。

static NSURL *remapFileURL(NSURL *url); // 定义在后面（LineFileManager 段）

static void logIfInteresting(NSString *from, NSString *to) {
    if ([from containsString:@"UserDefaults"] || [from.lastPathComponent hasSuffix:@".dict"]) {
        NSLog(@"[LineAccount] IO redirect %@ -> %@", from.lastPathComponent, to);
    }
}
static NSString *remapForWrite(NSString *path) {
    if (path.length == 0) return path;
    NSString *m = remapPath(path);
    if (m.length && ![m isEqualToString:path]) {
        mkdirp([m stringByDeletingLastPathComponent]);
        logIfInteresting(path, m);
        return m;
    }
    return path;
}
static NSURL *remapURLForWrite(NSURL *url) {
    NSString *op = nil;
    @try { op = url.path; } @catch (__unused id e) {}
    NSURL *u = remapFileURL(url); // 会为写入建好父目录
    if (u && op) { @try { logIfInteresting(op, u.path); } @catch (__unused id e) {} }
    return u ?: url;
}

// ---- NSData 写 ----
static BOOL (*orig_data_writeFileAtom)(id,SEL,NSString*,BOOL) = NULL;
static BOOL hk_data_writeFileAtom(id s, SEL c, NSString *p, BOOL a) {
    return orig_data_writeFileAtom(s, c, remapForWrite(p), a);
}
static BOOL (*orig_data_writeFileOpt)(id,SEL,NSString*,NSUInteger,NSError**) = NULL;
static BOOL hk_data_writeFileOpt(id s, SEL c, NSString *p, NSUInteger o, NSError **e) {
    return orig_data_writeFileOpt(s, c, remapForWrite(p), o, e);
}
static BOOL (*orig_data_writeURLAtom)(id,SEL,NSURL*,BOOL) = NULL;
static BOOL hk_data_writeURLAtom(id s, SEL c, NSURL *u, BOOL a) {
    return orig_data_writeURLAtom(s, c, remapURLForWrite(u), a);
}
static BOOL (*orig_data_writeURLOpt)(id,SEL,NSURL*,NSUInteger,NSError**) = NULL;
static BOOL hk_data_writeURLOpt(id s, SEL c, NSURL *u, NSUInteger o, NSError **e) {
    return orig_data_writeURLOpt(s, c, remapURLForWrite(u), o, e);
}
// ---- NSData 读 ----
static id (*orig_data_ctxFile)(id,SEL,NSString*) = NULL;
static id hk_data_ctxFile(id s, SEL c, NSString *p) {
    return orig_data_ctxFile(s, c, remapPath(p) ?: p);
}
static id (*orig_data_ctxFileOpt)(id,SEL,NSString*,NSUInteger,NSError**) = NULL;
static id hk_data_ctxFileOpt(id s, SEL c, NSString *p, NSUInteger o, NSError **e) {
    return orig_data_ctxFileOpt(s, c, remapPath(p) ?: p, o, e);
}
static id (*orig_data_initFile)(id,SEL,NSString*) = NULL;
static id hk_data_initFile(id s, SEL c, NSString *p) {
    return orig_data_initFile(s, c, remapPath(p) ?: p);
}

// ---- NSDictionary 写 ----
static BOOL (*orig_dict_writeFileAtom)(id,SEL,NSString*,BOOL) = NULL;
static BOOL hk_dict_writeFileAtom(id s, SEL c, NSString *p, BOOL a) {
    return orig_dict_writeFileAtom(s, c, remapForWrite(p), a);
}
static BOOL (*orig_dict_writeURLAtom)(id,SEL,NSURL*,BOOL) = NULL;
static BOOL hk_dict_writeURLAtom(id s, SEL c, NSURL *u, BOOL a) {
    return orig_dict_writeURLAtom(s, c, remapURLForWrite(u), a);
}
static BOOL (*orig_dict_writeURLErr)(id,SEL,NSURL*,NSError**) = NULL;
static BOOL hk_dict_writeURLErr(id s, SEL c, NSURL *u, NSError **e) {
    return orig_dict_writeURLErr(s, c, remapURLForWrite(u), e);
}
// ---- NSDictionary 读 ----
static id (*orig_dict_ctxFile)(id,SEL,NSString*) = NULL;
static id hk_dict_ctxFile(id s, SEL c, NSString *p) {
    return orig_dict_ctxFile(s, c, remapPath(p) ?: p);
}
static id (*orig_dict_initFile)(id,SEL,NSString*) = NULL;
static id hk_dict_initFile(id s, SEL c, NSString *p) {
    return orig_dict_initFile(s, c, remapPath(p) ?: p);
}

#define SWZ_INST(CLS, SELNAME, HOOK, ORIG, TYPE) do { \
    Method _m = class_getInstanceMethod([CLS class], @selector(SELNAME)); \
    if (_m) *(void **)&ORIG = (void *)method_setImplementation(_m, (IMP)HOOK); \
} while (0)
#define SWZ_CLS(CLS, SELNAME, HOOK, ORIG) do { \
    Method _m = class_getClassMethod([CLS class], @selector(SELNAME)); \
    if (_m) *(void **)&ORIG = (void *)method_setImplementation(_m, (IMP)HOOK); \
} while (0)

static void installFileIORedirect(void) {
    static BOOL done = NO;
    if (done) return; done = YES;

    // NSData 写
    SWZ_INST(NSData, writeToFile:atomically:,        hk_data_writeFileAtom, orig_data_writeFileAtom, 0);
    SWZ_INST(NSData, writeToFile:options:error:,     hk_data_writeFileOpt,  orig_data_writeFileOpt, 0);
    SWZ_INST(NSData, writeToURL:atomically:,         hk_data_writeURLAtom,  orig_data_writeURLAtom, 0);
    SWZ_INST(NSData, writeToURL:options:error:,      hk_data_writeURLOpt,   orig_data_writeURLOpt, 0);
    // NSData 读
    SWZ_CLS (NSData, dataWithContentsOfFile:,        hk_data_ctxFile,       orig_data_ctxFile);
    SWZ_CLS (NSData, dataWithContentsOfFile:options:error:, hk_data_ctxFileOpt, orig_data_ctxFileOpt);
    SWZ_INST(NSData, initWithContentsOfFile:,        hk_data_initFile,      orig_data_initFile, 0);

    // NSDictionary 写
    SWZ_INST(NSDictionary, writeToFile:atomically:,  hk_dict_writeFileAtom, orig_dict_writeFileAtom, 0);
    SWZ_INST(NSDictionary, writeToURL:atomically:,   hk_dict_writeURLAtom,  orig_dict_writeURLAtom, 0);
    SWZ_INST(NSDictionary, writeToURL:error:,        hk_dict_writeURLErr,   orig_dict_writeURLErr, 0);
    // NSDictionary 读
    SWZ_CLS (NSDictionary, dictionaryWithContentsOfFile:, hk_dict_ctxFile,  orig_dict_ctxFile);
    SWZ_INST(NSDictionary, initWithContentsOfFile:,  hk_dict_initFile,      orig_dict_initFile, 0);

    NSLog(@"[LineAccount] NSData/NSDictionary 文件 I/O 重定向已装（堵 .dict 共享泄漏）");
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

    // NSData/NSDictionary 文件 I/O 重定向（堵 backupUserDefaults.dict 等共享泄漏）
    installFileIORedirect();

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

// ★ 很多 LINE 子系统（Story/广告/Channel/CoreData 等）不走 NSHomeDirectory，
//   而是走这个 C 函数拿 Application Support / Caches / Documents 根 → 漏到真实 home。
//   必须一并重定向到槽，否则数据分裂 → 重启时 LINE 判定 session 损坏而注销。
static NSArray *(*orig_NSSearchPath)(NSSearchPathDirectory, NSSearchPathDomainMask, BOOL) = NULL;
static NSArray *hooked_NSSearchPath(NSSearchPathDirectory dir, NSSearchPathDomainMask mask, BOOL expand) {
    NSArray *r = orig_NSSearchPath ? orig_NSSearchPath(dir, mask, expand) : nil;
    if (g_selectedSlot < 1 || r.count == 0) return r;
    NSMutableArray *out = [NSMutableArray arrayWithCapacity:r.count];
    for (NSString *p in r) {
        NSString *m = remapPath(p);
        if (m.length && ![m isEqualToString:p]) mkdirp(m);
        [out addObject:(m ?: p)];
    }
    return out;
}

static void installHomeDirectoryHook(void) {
    static BOOL done = NO;
    if (done) return;
    done = YES;
    (void)realHomePath();
    if (!orig_NSHomeDirectory) {
        orig_NSHomeDirectory = (NSString *(*)(void))dlsym(RTLD_DEFAULT, "NSHomeDirectory");
    }
    if (!orig_NSSearchPath) {
        orig_NSSearchPath = (NSArray *(*)(NSSearchPathDirectory, NSSearchPathDomainMask, BOOL))
            dlsym(RTLD_DEFAULT, "NSSearchPathForDirectoriesInDomains");
    }
    struct rebinding rebs[2] = {
        {"NSHomeDirectory", (void *)hooked_NSHomeDirectory, (void **)&orig_NSHomeDirectory},
        {"NSSearchPathForDirectoriesInDomains", (void *)hooked_NSSearchPath, (void **)&orig_NSSearchPath},
    };
    rebind_symbols(rebs, 2);
    NSLog(@"[LineAccount] NSHomeDirectory + NSSearchPath -> slot when selected");
}

#pragma mark - CoreData store URL 强制重定向（堵死 split-brain 的关键）

// 不管 LINE 用什么方式拼出 store URL，一律在真正 addPersistentStore 前把它拉回槽。
// 这样 Talk / Story / 广告 / Channel / HomeTab 等所有 CoreData 都落在同一个 account_N，
// 重启时账号数据一致 → LINE 不再判定损坏而注销。
static IMP orig_addPersistentStore = NULL;
static id hooked_addPersistentStore(id self, SEL _cmd, id storeType, id configuration,
                                    NSURL *url, NSDictionary *options, NSError **error) {
    if (url) {
        NSString *p = url.path;
        if (p.length > 0) {
            if (g_selectedSlot >= 1) {
                NSString *mapped = remapPath(p);
                if (mapped.length && ![mapped isEqualToString:p]) {
                    url = [NSURL fileURLWithPath:mapped];
                    p = mapped;
                    NSLog(@"[LineAccount] addPersistentStore remap -> %@", mapped);
                }
            }
            // ★ 兜底：CoreData 加 SQLite store 前要求父目录已存在，否则抛
            //   NSInvalidArgumentException "Error validating url for store" → abort。
            //   典型受害者：App Group 里的 MessageExt.sqlite，其 .../PrivateStore/P_<mid>/Messages/
            //   由动态 mid 组成、系统不会预建。这里对任何 store 都先把父目录建齐。
            mkdirp([p stringByDeletingLastPathComponent]);
        }
    }
    return ((id(*)(id, SEL, id, id, NSURL *, NSDictionary *, NSError **))orig_addPersistentStore)
        (self, _cmd, storeType, configuration, url, options, error);
}

// ★ 最可靠的兜底点：LINE 的 Swift 代码经 objc_msgSend 调 NSPersistentContainer 的
//   loadPersistentStoresWithCompletionHandler:（CoreData 内部再调 addPersistentStore，
//   那层可能是直接 IMP 调用、swizzle 拦不到）。在这最外层把每个 store 的父目录建齐，
//   CoreData 校验前父目录就存在 → 不再抛 "Error validating url for store"。
typedef void (*LoadPS_t)(id, SEL, id);
static LoadPS_t orig_loadPersistentStores = NULL;

static void ensureStoreDescriptionDirs(id container) {
    @try {
        NSArray *descs = [container performSelector:@selector(persistentStoreDescriptions)];
        for (id d in descs) {
            NSURL *u = nil;
            @try { u = [d performSelector:@selector(URL)]; } @catch (__unused NSException *e) {}
            NSString *p = u.path;
            if (p.length > 0) {
                NSString *dir = [p stringByDeletingLastPathComponent];
                mkdirp(dir);
                NSLog(@"[LineAccount] CD ensure store dir: %@", dir);
            }
        }
    } @catch (NSException *e) {
        NSLog(@"[LineAccount] CD ensureStoreDescriptionDirs ex: %@", e);
    }
}

static void hooked_loadPersistentStores(id self, SEL _cmd, id completion) {
    ensureStoreDescriptionDirs(self);
    if (orig_loadPersistentStores) orig_loadPersistentStores(self, _cmd, completion);
}

static void installCoreDataRedirect(void) {
    static BOOL done = NO;
    if (done) return;
    done = YES;

    Class psc = NSClassFromString(@"NSPersistentStoreCoordinator");
    if (psc) {
        SEL sel = @selector(addPersistentStoreWithType:configuration:URL:options:error:);
        Method m = class_getInstanceMethod(psc, sel);
        if (m) {
            orig_addPersistentStore = method_setImplementation(m, (IMP)hooked_addPersistentStore);
            NSLog(@"[LineAccount] hooked addPersistentStore");
        }
    } else {
        NSLog(@"[LineAccount] NSPersistentStoreCoordinator missing");
    }

    // 关键兜底：NSPersistentContainer loadPersistentStores（LINE 直调，必拦得到）
    Class pc = NSClassFromString(@"NSPersistentContainer");
    if (pc) {
        SEL sel2 = @selector(loadPersistentStoresWithCompletionHandler:);
        Method m2 = class_getInstanceMethod(pc, sel2);
        if (m2) {
            orig_loadPersistentStores = (LoadPS_t)method_setImplementation(m2, (IMP)hooked_loadPersistentStores);
            NSLog(@"[LineAccount] hooked loadPersistentStores -> pre-create store dirs");
        } else {
            NSLog(@"[LineAccount] loadPersistentStores selector missing");
        }
    } else {
        NSLog(@"[LineAccount] NSPersistentContainer missing");
    }
}

#pragma mark - NSUserDefaults 隔离（登录态的真正存放处）

// NSHomeDirectory 重定向覆盖不到 NSUserDefaults：它由 cfprefsd 守护进程按
// applicationID 管理，写在真实容器的 Library/Preferences 下，进程内改 Home 无效。
// 于是所有容器共用同一份 → 账号1 的登录态泄漏到账号2、互相覆盖。
// 解决：把 +[NSUserDefaults standardUserDefaults] 换成「每槽独立 suite」，
// cfprefsd 按 suite 名分成 4 份独立 plist，天然隔离且跨重启持久。
static NSUserDefaults *g_slotDefaults = nil;
static NSInteger g_slotDefaultsForSlot = -1;
static IMP orig_standardUserDefaults = NULL;

static NSString *slotDefaultsSuiteName(NSInteger slot) {
    return [NSString stringWithFormat:@"LineAccountSlot%ld", (long)slot];
}

static NSUserDefaults *hooked_standardUserDefaults(id self, SEL _cmd) {
    if (g_selectedSlot >= 1) {
        if (!g_slotDefaults || g_slotDefaultsForSlot != g_selectedSlot) {
            g_slotDefaults = [[NSUserDefaults alloc]
                              initWithSuiteName:slotDefaultsSuiteName(g_selectedSlot)];
            g_slotDefaultsForSlot = g_selectedSlot;
            NSLog(@"[LineAccount] standardUserDefaults -> suite %@", slotDefaultsSuiteName(g_selectedSlot));
        }
        return g_slotDefaults;
    }
    if (orig_standardUserDefaults) {
        return ((NSUserDefaults *(*)(id, SEL))orig_standardUserDefaults)(self, _cmd);
    }
    return nil;
}

// ★ 关键补丁：LINE 用 -[NSUserDefaults initWithSuiteName:] 直接绑到自己的 bundle 域(或传 nil)
// 拿到「bundle 域 defaults 实例」写 mid，其读写走 Foundation→cfprefsd 内部 XPC，
// 绕过 +standardUserDefaults 交换与 CFPreferences fishhook。→ mid 泄漏到共享 jp.naver.line.plist。
// 这里把 nil / bundleID 域统一重定向到按槽 suite（与 standardUserDefaults 归一到同一份 LineAccountSlotN.plist）。
static id (*orig_initWithSuiteName)(id, SEL, NSString *) = NULL;
static id hooked_initWithSuiteName(id self, SEL _cmd, NSString *suiteName) {
    if (g_selectedSlot >= 1) {
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
        BOOL isBundleDomain = (suiteName == nil) || (suiteName.length == 0) ||
                              (bid.length && [suiteName isEqualToString:bid]);
        if (isBundleDomain) {
            NSString *slotSuite = slotDefaultsSuiteName(g_selectedSlot);
            NSLog([NSString stringWithFormat:@"[LineAccount] initWithSuiteName IN=%@ -> %@",
                   suiteName ?: @"(nil)", slotSuite]);
            return orig_initWithSuiteName(self, _cmd, slotSuite);
        }
    }
    return orig_initWithSuiteName(self, _cmd, suiteName);
}

static void installUserDefaultsIsolation(void) {
    static BOOL done = NO;
    if (done) return;
    done = YES;
    Method m = class_getClassMethod([NSUserDefaults class], @selector(standardUserDefaults));
    if (!m) {
        NSLog(@"[LineAccount] standardUserDefaults method missing");
        return;
    }
    orig_standardUserDefaults = method_setImplementation(m, (IMP)hooked_standardUserDefaults);
    NSLog(@"[LineAccount] hooked +[NSUserDefaults standardUserDefaults] -> per-slot suite");

    // 实例级：把 bundle 域 defaults 归一到按槽 suite（堵住 mid 泄漏共享域的真正入口）
    Method mi = class_getInstanceMethod([NSUserDefaults class], @selector(initWithSuiteName:));
    if (mi) {
        orig_initWithSuiteName = (id (*)(id, SEL, NSString *))method_getImplementation(mi);
        method_setImplementation(mi, (IMP)hooked_initWithSuiteName);
        NSLog(@"[LineAccount] hooked -[NSUserDefaults initWithSuiteName:] (nil/bundleID -> per-slot suite)");
    } else {
        NSLog(@"[LineAccount] initWithSuiteName: method missing");
    }
}

#pragma mark - CFPreferences 按槽重定向（堵住 mid 等身份泄漏到共享 bundle 域）

// 关键发现：LINE 把 mid（当前账号）通过 CFPreferences 直接写共享 bundle 域
// jp.naver.line.9YV3UM7J6Z.plist，还会从 backupUserDefaults.dict 恢复到该域，
// 完全绕过我们的 standardUserDefaults suite。→ 各槽都读到同一个 mid = 同一个账号 = 聊天混。
// 解决：在 CFPreferences C 层，把「本 app 的偏好域」(bundle id 或 current-app 哨兵)
// 统一重定向到 LineAccountSlotN（与 suite 同名，读写归一到同一份按槽 plist）。
// ★ bundle id 运行时动态取（重签后会变，绝不能硬编码）。
static CFStringRef appBundleID(void) {
    static CFStringRef cached = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
        if (bid.length) cached = (CFStringRef)CFBridgingRetain(bid);
    });
    return cached;
}

static CFStringRef g_slotAppIDCache = NULL;
static NSInteger g_slotAppIDForSlot = -1;
static CFStringRef currentSlotAppID(void) {
    if (g_selectedSlot < 1) return NULL;
    if (!g_slotAppIDCache || g_slotAppIDForSlot != g_selectedSlot) {
        if (g_slotAppIDCache) { CFRelease(g_slotAppIDCache); g_slotAppIDCache = NULL; }
        NSString *s = [NSString stringWithFormat:@"LineAccountSlot%ld", (long)g_selectedSlot];
        g_slotAppIDCache = (CFStringRef)CFBridgingRetain(s);
        g_slotAppIDForSlot = g_selectedSlot;
    }
    return g_slotAppIDCache;
}
static CFStringRef remapAppID(CFStringRef appID) {
    if (g_selectedSlot < 1 || appID == NULL) return appID;
    CFStringRef bid = appBundleID();
    if (appID == kCFPreferencesCurrentApplication ||
        CFStringCompare(appID, CFSTR("kCFPreferencesCurrentApplication"), 0) == kCFCompareEqualTo ||
        (bid && CFStringCompare(appID, bid, 0) == kCFCompareEqualTo)) {
        CFStringRef s = currentSlotAppID();
        return s ? s : appID;
    }
    return appID;
}

typedef CFPropertyListRef (*CFPCopyAppValue_t)(CFStringRef, CFStringRef);
typedef void (*CFPSetAppValue_t)(CFStringRef, CFPropertyListRef, CFStringRef);
typedef Boolean (*CFPAppSync_t)(CFStringRef);
typedef CFArrayRef (*CFPCopyKeyList_t)(CFStringRef, CFStringRef, CFStringRef);
typedef Boolean (*CFPAppValueIsForced_t)(CFStringRef, CFStringRef);
typedef CFDictionaryRef (*CFPCopyMultiple_t)(CFArrayRef, CFStringRef, CFStringRef, CFStringRef);
typedef void (*CFPSetMultiple_t)(CFDictionaryRef, CFArrayRef, CFStringRef, CFStringRef, CFStringRef);
typedef CFPropertyListRef (*CFPCopyValue_t)(CFStringRef, CFStringRef, CFStringRef, CFStringRef);
typedef void (*CFPSetValue_t)(CFStringRef, CFPropertyListRef, CFStringRef, CFStringRef, CFStringRef);
typedef Boolean (*CFPSync_t)(CFStringRef, CFStringRef, CFStringRef);
typedef CFIndex (*CFPGetAppInt_t)(CFStringRef, CFStringRef, Boolean *);
typedef Boolean (*CFPGetAppBool_t)(CFStringRef, CFStringRef, Boolean *);

static CFPCopyAppValue_t     orig_CFPCopyAppValue = NULL;
static CFPSetAppValue_t      orig_CFPSetAppValue = NULL;
static CFPAppSync_t          orig_CFPAppSync = NULL;
static CFPCopyKeyList_t      orig_CFPCopyKeyList = NULL;
static CFPAppValueIsForced_t orig_CFPAppValueIsForced = NULL;
static CFPCopyMultiple_t     orig_CFPCopyMultiple = NULL;
static CFPSetMultiple_t      orig_CFPSetMultiple = NULL;
static CFPCopyValue_t        orig_CFPCopyValue = NULL;
static CFPSetValue_t         orig_CFPSetValue = NULL;
static CFPSync_t             orig_CFPSync = NULL;
static CFPGetAppInt_t        orig_CFPGetAppInt = NULL;
static CFPGetAppBool_t       orig_CFPGetAppBool = NULL;

static CFPropertyListRef hooked_CFPCopyAppValue(CFStringRef key, CFStringRef app) {
    return orig_CFPCopyAppValue(key, remapAppID(app));
}
static void hooked_CFPSetAppValue(CFStringRef key, CFPropertyListRef val, CFStringRef app) {
    orig_CFPSetAppValue(key, val, remapAppID(app));
}
static Boolean hooked_CFPAppSync(CFStringRef app) {
    return orig_CFPAppSync(remapAppID(app));
}
static CFArrayRef hooked_CFPCopyKeyList(CFStringRef app, CFStringRef user, CFStringRef host) {
    return orig_CFPCopyKeyList(remapAppID(app), user, host);
}
static Boolean hooked_CFPAppValueIsForced(CFStringRef key, CFStringRef app) {
    return orig_CFPAppValueIsForced(key, remapAppID(app));
}
static CFDictionaryRef hooked_CFPCopyMultiple(CFArrayRef keys, CFStringRef app, CFStringRef user, CFStringRef host) {
    return orig_CFPCopyMultiple(keys, remapAppID(app), user, host);
}
static void hooked_CFPSetMultiple(CFDictionaryRef set, CFArrayRef rm, CFStringRef app, CFStringRef user, CFStringRef host) {
    orig_CFPSetMultiple(set, rm, remapAppID(app), user, host);
}
static CFPropertyListRef hooked_CFPCopyValue(CFStringRef key, CFStringRef app, CFStringRef user, CFStringRef host) {
    return orig_CFPCopyValue(key, remapAppID(app), user, host);
}
static void hooked_CFPSetValue(CFStringRef key, CFPropertyListRef val, CFStringRef app, CFStringRef user, CFStringRef host) {
    orig_CFPSetValue(key, val, remapAppID(app), user, host);
}
static Boolean hooked_CFPSync(CFStringRef app, CFStringRef user, CFStringRef host) {
    return orig_CFPSync(remapAppID(app), user, host);
}
static CFIndex hooked_CFPGetAppInt(CFStringRef key, CFStringRef app, Boolean *ok) {
    return orig_CFPGetAppInt(key, remapAppID(app), ok);
}
static Boolean hooked_CFPGetAppBool(CFStringRef key, CFStringRef app, Boolean *ok) {
    return orig_CFPGetAppBool(key, remapAppID(app), ok);
}

static void installPrefsRedirect(void) {
    static BOOL done = NO;
    if (done) return;
    done = YES;
    orig_CFPCopyAppValue     = (CFPCopyAppValue_t)dlsym(RTLD_DEFAULT, "CFPreferencesCopyAppValue");
    orig_CFPSetAppValue      = (CFPSetAppValue_t)dlsym(RTLD_DEFAULT, "CFPreferencesSetAppValue");
    orig_CFPAppSync          = (CFPAppSync_t)dlsym(RTLD_DEFAULT, "CFPreferencesAppSynchronize");
    orig_CFPCopyKeyList      = (CFPCopyKeyList_t)dlsym(RTLD_DEFAULT, "CFPreferencesCopyKeyList");
    orig_CFPAppValueIsForced = (CFPAppValueIsForced_t)dlsym(RTLD_DEFAULT, "CFPreferencesAppValueIsForced");
    orig_CFPCopyMultiple     = (CFPCopyMultiple_t)dlsym(RTLD_DEFAULT, "CFPreferencesCopyMultiple");
    orig_CFPSetMultiple      = (CFPSetMultiple_t)dlsym(RTLD_DEFAULT, "CFPreferencesSetMultiple");
    orig_CFPCopyValue        = (CFPCopyValue_t)dlsym(RTLD_DEFAULT, "CFPreferencesCopyValue");
    orig_CFPSetValue         = (CFPSetValue_t)dlsym(RTLD_DEFAULT, "CFPreferencesSetValue");
    orig_CFPSync             = (CFPSync_t)dlsym(RTLD_DEFAULT, "CFPreferencesSynchronize");
    orig_CFPGetAppInt        = (CFPGetAppInt_t)dlsym(RTLD_DEFAULT, "CFPreferencesGetAppIntegerValue");
    orig_CFPGetAppBool       = (CFPGetAppBool_t)dlsym(RTLD_DEFAULT, "CFPreferencesGetAppBooleanValue");

    struct rebinding rebs[12] = {
        {"CFPreferencesCopyAppValue",      (void *)hooked_CFPCopyAppValue,     (void **)&orig_CFPCopyAppValue},
        {"CFPreferencesSetAppValue",       (void *)hooked_CFPSetAppValue,      (void **)&orig_CFPSetAppValue},
        {"CFPreferencesAppSynchronize",    (void *)hooked_CFPAppSync,          (void **)&orig_CFPAppSync},
        {"CFPreferencesCopyKeyList",       (void *)hooked_CFPCopyKeyList,      (void **)&orig_CFPCopyKeyList},
        {"CFPreferencesAppValueIsForced",  (void *)hooked_CFPAppValueIsForced, (void **)&orig_CFPAppValueIsForced},
        {"CFPreferencesCopyMultiple",      (void *)hooked_CFPCopyMultiple,     (void **)&orig_CFPCopyMultiple},
        {"CFPreferencesSetMultiple",       (void *)hooked_CFPSetMultiple,      (void **)&orig_CFPSetMultiple},
        {"CFPreferencesCopyValue",         (void *)hooked_CFPCopyValue,        (void **)&orig_CFPCopyValue},
        {"CFPreferencesSetValue",          (void *)hooked_CFPSetValue,         (void **)&orig_CFPSetValue},
        {"CFPreferencesSynchronize",       (void *)hooked_CFPSync,             (void **)&orig_CFPSync},
        {"CFPreferencesGetAppIntegerValue",(void *)hooked_CFPGetAppInt,        (void **)&orig_CFPGetAppInt},
        {"CFPreferencesGetAppBooleanValue",(void *)hooked_CFPGetAppBool,       (void **)&orig_CFPGetAppBool},
    };
    rebind_symbols(rebs, 12);
    NSLog(@"[LineAccount] CFPreferences 按槽重定向已安装 (bundle/current-app -> LineAccountSlotN)");
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

// register 被桩掉后，LINE 仍会 submitTaskRequest: 提交未注册 handler 的任务，
// iOS 抛 NSInternalInconsistencyException "No launch handler registered" → abort。
// 一并桩掉 submit：直接返回 YES(成功) 且不真正提交，避免异常。
static BOOL hooked_BGTaskScheduler_submit(id self, SEL _cmd, id request, NSError **error) {
    (void)self; (void)_cmd; (void)request;
    if (error) *error = nil;
    NSLog(@"[LineAccount] stub BGTaskScheduler submitTaskRequest (skip, avoid no-handler abort)");
    return YES;
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

    SEL selSubmit = @selector(submitTaskRequest:error:);
    Method mSubmit = class_getInstanceMethod(cls, selSubmit);
    if (mSubmit) {
        method_setImplementation(mSubmit, (IMP)hooked_BGTaskScheduler_submit);
        NSLog(@"[LineAccount] hooked -[BGTaskScheduler submitTaskRequest:error:] -> no-op");
    }

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

#pragma mark - 容器交换（core：让 LINE 永远用真实 Home，选账号时搬数据实现隔离）

// 用 POSIX 枚举目录子项，绕开所有 ObjC/NSFileManager hook（交换时 g_selectedSlot 已设，
// 走 NSFileManager 可能被 remap 到错误路径）。
static NSArray<NSString *> *listChildrenPOSIX(NSString *dir) {
    NSMutableArray *out = [NSMutableArray array];
    const char *c = [dir fileSystemRepresentation];
    if (!c) return out;
    DIR *d = opendir(c);
    if (!d) return out;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        NSString *n = [NSString stringWithUTF8String:e->d_name];
        if (n) [out addObject:n];
    }
    closedir(d);
    return out;
}

// ★ 动态交换集：把 base(=Home 或某个槽) 里「需要按账号隔离」的相对路径全列出来。
// 策略：除白名单外，Home 顶层项 + Library 下的子项全部纳入交换 —— 这样无论备忘录/Keep/
// 各种 CoreData 落在哪个目录都会被隔离，避免"固定 6 目录漏掉某类数据"的老问题。
// 顶层排除：Library(单独展开其子项)、SystemData/tmp(瞬态)、容器元数据 plist。
// Library 内排除：LineSlots(我们的槽存储本身)、Preferences(cfprefsd 内存缓存，换文件无效，
//                改由 NSUserDefaults suite + CFPreferences 按槽重定向隔离)。
static NSArray<NSString *> *swapRelItemsUnder(NSString *base) {
    NSMutableArray *items = [NSMutableArray array];
    NSSet *skipTop = [NSSet setWithArray:@[
        @"Library", @"SystemData", @"tmp",
        @".com.apple.mobile_container_manager.metadata.plist",
        @".used", @".current", @".journal", @"meta.plist",
    ]];
    for (NSString *name in listChildrenPOSIX(base)) {
        if ([skipTop containsObject:name]) continue;
        [items addObject:name];
    }
    NSSet *skipLib = [NSSet setWithArray:@[@"LineSlots", @"Preferences"]];
    NSString *lib = [base stringByAppendingPathComponent:@"Library"];
    for (NSString *name in listChildrenPOSIX(lib)) {
        if ([skipLib containsObject:name]) continue;
        [items addObject:[@"Library" stringByAppendingPathComponent:name]];
    }
    return items;
}

static NSString *swapStatePath(NSString *name) {
    return [slotsRootPath() stringByAppendingPathComponent:name];
}
static NSInteger readCurrentSlot(void) {
    NSString *s = [NSString stringWithContentsOfFile:swapStatePath(@".current")
                                            encoding:NSUTF8StringEncoding error:nil];
    return s ? s.integerValue : 0;
}
static void writeCurrentSlot(NSInteger slot) {
    mkdirp(slotsRootPath());
    [[NSString stringWithFormat:@"%ld", (long)slot]
        writeToFile:swapStatePath(@".current") atomically:YES
           encoding:NSUTF8StringEncoding error:nil];
}
static void writeJournal(NSInteger from, NSInteger to, NSString *phase) {
    mkdirp(slotsRootPath());
    [[NSString stringWithFormat:@"%ld,%ld,%@", (long)from, (long)to, phase]
        writeToFile:swapStatePath(@".journal") atomically:YES
           encoding:NSUTF8StringEncoding error:nil];
}
static void clearJournal(void) {
    removePathPOSIX(swapStatePath(@".journal"));
}

static BOOL posixExists(NSString *p) {
    if (p.length == 0) return NO;
    struct stat st;
    return lstat([p fileSystemRepresentation], &st) == 0;
}
static BOOL posixIsDir(NSString *p) {
    if (p.length == 0) return NO;
    struct stat st;
    if (lstat([p fileSystemRepresentation], &st) != 0) return NO;
    return S_ISDIR(st.st_mode);
}

// 原子移动一个顶层项（目录/文件）。src 不存在视为成功（等价于空）。
// iOS 容器管理器会「钉住」Documents / Library/Caches 等系统目录，整体 rename 会 EPERM(errno=1)。
// 这种情况退化为「逐个搬子项」：目标目录建好，把 src 的每个子项 rename 进去，再删空 src。
static BOOL moveOne(NSString *src, NSString *dst) {
    if (!posixExists(src)) return YES;
    mkdirp([dst stringByDeletingLastPathComponent]);
    if (posixIsDir(src)) {
        // 仅当 dst 不存在时才做整体 rename；存在(残留)时直接走逐项合并，避免误删已有数据
        if (!posixExists(dst)) {
            if (rename([src fileSystemRepresentation], [dst fileSystemRepresentation]) == 0) return YES;
            // rename 失败(通常 EPERM/EXDEV)：退化为逐项搬
        }
        mkdirp(dst);
        BOOL allOK = YES;
        for (NSString *child in listChildrenPOSIX(src)) {
            NSString *cs = [src stringByAppendingPathComponent:child];
            NSString *cd = [dst stringByAppendingPathComponent:child];
            if (!moveOne(cs, cd)) allOK = NO;   // 递归：深层若同样受限继续退化
        }
        rmdir([src fileSystemRepresentation]);   // src 应已空；失败无害(空目录残留不影响隔离)
        return allOK;
    }
    // 文件：dst 需不存在
    removePathPOSIX(dst);
    if (rename([src fileSystemRepresentation], [dst fileSystemRepresentation]) == 0) return YES;
    NSLog(@"[LineAccount] SWAP rename FAIL errno=%d %@ -> %@", errno, src, dst);
    return NO;
}

static NSString *homeRel(NSString *rel) {
    return [realHomePath() stringByAppendingPathComponent:rel];
}
static NSString *slotRel(NSInteger slot, NSString *rel) {
    return [slotHomePath(slot) stringByAppendingPathComponent:rel]; // slotHomePath = LineSlots/account_N
}

// 把当前 Home 里的账号数据搬进 slot（幂等，可重复执行）。枚举 Home 现有内容为准。
static void drainHomeToSlot(NSInteger slot) {
    if (slot < 1) return;
    NSArray *items = swapRelItemsUnder(realHomePath());
    for (NSString *rel in items) {
        moveOne(homeRel(rel), slotRel(slot, rel));
    }
    NSLog(@"[LineAccount] SWAP drained Home -> slot %ld (%lu items)", (long)slot, (unsigned long)items.count);
}
// 把 slot 里的账号数据搬回 Home（幂等，可重复执行）。枚举槽内现有内容为准。
static void fillHomeFromSlot(NSInteger slot) {
    if (slot < 1) return;
    NSArray *items = swapRelItemsUnder(slotHomePath(slot));
    for (NSString *rel in items) {
        moveOne(slotRel(slot, rel), homeRel(rel));
    }
    // 确保基本目录在（LINE 首次进空槽也要有骨架）
    mkdirp(homeRel(@"Library/Application Support"));
    mkdirp(homeRel(@"Documents"));
    NSLog(@"[LineAccount] SWAP filled slot %ld -> Home (%lu items)", (long)slot, (unsigned long)items.count);
}

#pragma mark - Keychain 交换（激活槽用原生无前缀凭证；非激活槽存 line.slot.N.*）
// Keychain 不在 Home 内、删 App 也不清除，无法随文件交换。故这里用 SecItemUpdate 给
// account 改名的方式，把整套凭证在「无前缀(激活)」与「line.slot.N.(停放)」之间搬移：
//   drain(from): 把当前激活(无前缀)凭证 → 加前缀 line.slot.from.*  （停放）
//   fill(to)   : 把 line.slot.to.* 凭证 → 去前缀  （成为激活，LINE 原生读取）
// 只改 account，不动 service —— (service, account) 是 genp 主键，account 带槽前缀即可区分，
// 且激活项 service 保持原样，LINE 用原生 query 就能命中。

static SecItemCopyMatching_t kcCopy(void) {
    return orig_SecItemCopyMatching ?: (SecItemCopyMatching_t)dlsym(RTLD_DEFAULT, "SecItemCopyMatching");
}
static SecItemUpdate_t kcUpdate(void) {
    return orig_SecItemUpdate ?: (SecItemUpdate_t)dlsym(RTLD_DEFAULT, "SecItemUpdate");
}
static SecItemDelete_t kcDelete(void) {
    return orig_SecItemDelete ?: (SecItemDelete_t)dlsym(RTLD_DEFAULT, "SecItemDelete");
}

static NSArray *kcAllItems(CFTypeRef klass) {
    NSDictionary *q = @{
        (__bridge id)kSecClass:            (__bridge id)klass,
        (__bridge id)kSecMatchLimit:       (__bridge id)kSecMatchLimitAll,
        (__bridge id)kSecReturnAttributes: (__bridge id)kCFBooleanTrue,
    };
    SecItemCopyMatching_t f = kcCopy();
    if (!f) return @[];
    CFTypeRef res = NULL;
    OSStatus st = f((__bridge CFDictionaryRef)q, &res);
    if (st != errSecSuccess || !res) return @[];
    if (CFGetTypeID(res) != CFArrayGetTypeID()) { CFRelease(res); return @[]; }
    return (__bridge_transfer NSArray *)res;
}

static BOOL kcHasAnySlotPrefix(NSString *s) {
    return s.length > 0 && [s hasPrefix:@"line.slot."];
}

// 用 (klass, oldAcct[, svce]) 唯一定位一条，把 account 改成 newAcct。幂等、容错。
static BOOL kcRenameAccount(CFTypeRef klass, NSString *oldAcct, NSString *svce, NSString *newAcct) {
    if (oldAcct.length == 0 || newAcct.length == 0 || [oldAcct isEqualToString:newAcct]) return YES;
    NSMutableDictionary *query = [@{
        (__bridge id)kSecClass:       (__bridge id)klass,
        (__bridge id)kSecAttrAccount: oldAcct,
    } mutableCopy];
    if (svce.length > 0) query[(__bridge id)kSecAttrService] = svce;

    NSDictionary *attrs = @{ (__bridge id)kSecAttrAccount: newAcct };
    SecItemUpdate_t up = kcUpdate();
    if (!up) return NO;
    OSStatus st = up((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attrs);
    if (st == errSecSuccess || st == errSecItemNotFound) return YES;
    if (st == errSecDuplicateItem) {
        // 目标名已存在（多为上次残留未搬回）→ 删掉冗余源项，保留已存在的目标
        SecItemDelete_t del = kcDelete();
        if (del) del((__bridge CFDictionaryRef)query);
        NSLog(@"[LineAccount] KC dup, dropped source acct=%@ svce=%@", oldAcct, svce);
        return YES;
    }
    NSLog(@"[LineAccount] KC rename FAIL st=%d acct=%@ -> %@ svce=%@", (int)st, oldAcct, newAcct, svce);
    return NO;
}

static void keychainSwap(NSInteger slot, BOOL addPrefix) {
    if (slot < 1 || slot > ACCOUNT_COUNT) return;
    NSString *prefix = slotKeyPrefix(slot);   // line.slot.N.
    CFTypeRef classes[] = { kSecClassGenericPassword, kSecClassInternetPassword };
    int changed = 0;
    for (int ci = 0; ci < 2; ci++) {
        CFTypeRef klass = classes[ci];
        for (NSDictionary *it in kcAllItems(klass)) {
            id acctObj = it[(__bridge id)kSecAttrAccount];
            id svceObj = it[(__bridge id)kSecAttrService];
            NSString *acct = [acctObj isKindOfClass:[NSString class]] ? acctObj : nil;
            NSString *svce = [svceObj isKindOfClass:[NSString class]] ? svceObj : nil;
            if (acct.length == 0) continue;   // 只处理有 account 的项

            if (addPrefix) {
                if (kcHasAnySlotPrefix(acct)) continue;         // 已带任意槽前缀 → 不是激活项，跳过
                if (kcRenameAccount(klass, acct, svce, [prefix stringByAppendingString:acct])) changed++;
            } else {
                if (![acct hasPrefix:prefix]) continue;          // 只搬本槽的
                if (kcRenameAccount(klass, acct, svce, [acct substringFromIndex:prefix.length])) changed++;
            }
        }
    }
    NSLog(@"[LineAccount] KC swap slot %ld addPrefix=%d changed=%d", (long)slot, addPrefix, changed);
}

static void drainKeychainToSlot(NSInteger slot)  { keychainSwap(slot, YES); }
static void fillKeychainFromSlot(NSInteger slot) { keychainSwap(slot, NO); }

// 切换到目标槽：先把上一个账号的实时数据搬回它的槽，再把目标槽数据搬进 Home。
static void swapToSlot(NSInteger to) {
    if (to < 1 || to > ACCOUNT_COUNT) return;
    NSInteger from = readCurrentSlot();
    if (from == to) {
        NSLog(@"[LineAccount] SWAP same slot %ld，Home 数据原样保留（重开同账号）", (long)to);
        return;
    }
    NSLog(@"[LineAccount] SWAP %ld -> %ld begin", (long)from, (long)to);
    writeJournal(from, to, @"drain");
    if (from >= 1) {
        drainHomeToSlot(from);
        drainKeychainToSlot(from);       // 上一号的凭证 → line.slot.from.*（停放）
    }
    writeCurrentSlot(0);                 // Home 已清空（数据在各槽），中间安全静止点
    writeJournal(from, to, @"fill");
    fillHomeFromSlot(to);
    fillKeychainFromSlot(to);            // 目标槽凭证 → 去前缀，成为 LINE 原生激活凭证
    writeCurrentSlot(to);
    clearJournal();
    NSLog(@"[LineAccount] SWAP %ld -> %ld done", (long)from, (long)to);
}

// 启动时若发现上次交换被中断，完成它（drain/fill 都幂等，直接补跑对应阶段）
static void recoverSwapJournalIfAny(void) {
    NSString *j = [NSString stringWithContentsOfFile:swapStatePath(@".journal")
                                            encoding:NSUTF8StringEncoding error:nil];
    if (j.length == 0) return;
    NSArray *parts = [j componentsSeparatedByString:@","];
    if (parts.count < 3) { clearJournal(); return; }
    NSInteger from = [parts[0] integerValue];
    NSInteger to   = [parts[1] integerValue];
    NSString *phase = parts[2];
    NSLog(@"[LineAccount] SWAP 检测到中断的交换 from=%ld to=%ld phase=%@ — 自愈中",
          (long)from, (long)to, phase);
    if ([phase isEqualToString:@"drain"]) {
        if (from >= 1) { drainHomeToSlot(from); drainKeychainToSlot(from); }
        writeCurrentSlot(0);             // 停在「Home 空、数据在槽」，交给选择页重新决定
    } else { // fill
        fillHomeFromSlot(to);
        fillKeychainFromSlot(to);
        writeCurrentSlot(to);
    }
    clearJournal();
    NSLog(@"[LineAccount] SWAP 自愈完成");
}

static void enterAccountSlot(NSInteger slot) {
    if (slot < 1 || slot > ACCOUNT_COUNT) return;

    mkdirp(slotHomePath(slot));
    [[NSData data] writeToFile:[slotHomePath(slot) stringByAppendingPathComponent:@".used"] atomically:YES];

    // 仅用于 UI 上标记「已有数据」
    NSMutableDictionary *meta = loadMeta();
    meta[@"selectedSlot"] = @(slot);
    saveMeta(meta);

    g_selectedSlot = slot;   // Keychain 前缀 + NSUserDefaults suite 按此隔离
    NSLog(@"[LineAccount] selected slot %ld — 容器交换 + 放行", (long)slot);

    // ★ 核心：把该账号数据搬进真实 Home（此时 didFinishLaunching/scene 仍被拦，Home 无写句柄，安全）
    swapToSlot(slot);

    // 崩溃防护（App Group 目录也已就绪）
    installIntentsCrashGuards();
    installBGTaskCrashGuards();
    installTalkDBAccountHooks();
    installCoreDataRedirect();       // ★ 给每个 CoreData store 兜底建父目录，堵 "Error validating url"

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

    // ★ 若上次「容器交换」被中途杀死，先自愈（把 Home 恢复到一致状态），再弹选择页
    recoverSwapJournalIfAny();

    NSLog(@"[LineAccount] ========================================");
    NSLog(@"[LineAccount] BUILD=%@", LINE_BUILD_ID);
    NSLog(@"[LineAccount] multi-account: 每次冷启动都弹选择页 → 选中进入该账号（容器交换隔离）");
    NSLog(@"[LineAccount] ========================================");
    // ★ 版本落地文件：时序无关，probe/人工都能直接读，确认设备上到底跑哪版 dylib
    [LINE_BUILD_ID writeToFile:swapStatePath(@".build") atomically:YES
                      encoding:NSUTF8StringEncoding error:nil];

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
    installUserDefaultsIsolation();
    installPrefsRedirect();          // ★ CFPreferences 按槽重定向：堵 mid 泄漏到共享 bundle 域
    installUIApplicationMainHook();
    installIntentsCrashGuards();
    installBGTaskCrashGuards();
    hookAppDelegate();

    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_needPicker && !g_launchResumed) showAccountPicker();
    });
}
