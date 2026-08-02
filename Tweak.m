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
#import <sys/socket.h>
#import <sys/time.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <netdb.h>
#import <fcntl.h>
#import <pthread.h>
#import <unistd.h>
#import <dirent.h>
#import <errno.h>
#import <stdlib.h>
#import <stdio.h>

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Wunused-function"

// 前置声明：屏上日志（定义在文件后半段，诊断代码需提前用）
static void la_flog(NSString *line);
// 前置声明：App Group 偏好域登记（hooked_containerURL 定义在前，实现在后）
static void la_recordAppGroup(NSString *gid);

#define ACCOUNT_COUNT 100000
#define SLOT_DIR_NAME @"LineAccountSlots"
#define SELECTED_SLOT_KEY @"LineAccount.SelectedSlot"
#define LINE_BUILD_ID @"got-swift-b v31"
// ★ v27：方案 C（本地 HTTP CONNECT 中继）。0=启用；1=完全不装（仅调试）
#define LA_DISABLE_ALL_PROXY_INJECT 0
// ★ v28：方案 B（GOT 重绑 Swift NWConnection.init → 本地中继）。1=用 B（26 安全，不写 __TEXT）
#define LA_USE_SCHEME_B 1
// LINE 导入的 Swift 符号：NWConnection.__allocating_init(to:using:)
#define LA_NWCONN_INIT_SYM "$s7Network12NWConnectionC2to5usingAcA10NWEndpointO_AA12NWParametersCtcfc"
// 稍后换域名只改这两处
#define LA_CONFIG_API_BASE @"https://www.khpturuy.vip/api"
#define LA_CONFIG_HOST @"www.khpturuy.vip"   // 拉配置必须直连，不能走账号代理

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
    // 登记 App 实际用到的每个 App Group，供偏好域按槽搬运（KakaoTalk 的 group 偏好域隔离靠这个）
    la_recordAppGroup(groupId);
    static int g_grpLogLeft = 30;
    if (g_grpLogLeft > 0) { g_grpLogLeft--; la_flog([NSString stringWithFormat:@"[grp] containerURL group=%@", groupId]); }
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

#pragma mark - 远程账号配置（设备 uuid → 后台 JSON）

@interface LARemoteAccount : NSObject
@property(nonatomic, assign) NSInteger slot;
@property(nonatomic, copy) NSString *name;
@property(nonatomic, copy) NSString *proxyHost;
@property(nonatomic, copy) NSString *proxyPort;
@property(nonatomic, copy) NSString *proxyUser;
@property(nonatomic, copy) NSString *proxyPass;
@property(nonatomic, copy) NSString *proxyType; // http / socks5，默认 http
@end
@implementation LARemoteAccount
@end

static NSArray<LARemoteAccount *> *g_remoteAccounts = nil;
static NSString *g_remoteFetchError = nil;
static BOOL g_remoteFetchDone = NO;
// 代理当前生效槽（选择页之前就要有值，定义见代理段 la_setProxyActiveSlot）
static NSInteger g_proxyActiveSlot = 0;
static void la_invalidateProxyCache(void);
static void la_setProxyActiveSlot(NSInteger slot);

static NSString *remoteConfigCachePath(void) {
    return [slotsRootPath() stringByAppendingPathComponent:@".remote_accounts.json"];
}

// ★ UUID 加固：除 keychain 外再在 slotsRootPath 落一份文件副本。
//   文件不受「锁屏(AfterFirstUnlock)/keychain 搬家/重签换 access group」影响，
//   是 UUID 稳定的主保险；keychain 作为跨重装的备份。slotsRootPath 不在交换集内，安全。
static NSString *deviceIdFilePath(void) {
    return [slotsRootPath() stringByAppendingPathComponent:@".device_id"];
}
static NSString *fileReadDeviceId(void) {
    NSString *s = [NSString stringWithContentsOfFile:deviceIdFilePath()
                                            encoding:NSUTF8StringEncoding error:nil];
    s = [s stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    return s.length > 0 ? s : nil;
}
static void fileWriteDeviceId(NSString *value) {
    if (value.length == 0) return;
    mkdirp(slotsRootPath());
    [value writeToFile:deviceIdFilePath() atomically:YES
              encoding:NSUTF8StringEncoding error:nil];
}

static NSString *kcReadDeviceId(void) {
    NSDictionary *q = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"LineAccount.DeviceId",
        (__bridge id)kSecAttrAccount: @"client",
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
    };
    CFTypeRef out = NULL;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)q, &out) != errSecSuccess || !out) return nil;
    NSData *data = CFBridgingRelease(out);
    if (data.length == 0) return nil;
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

static void kcWriteDeviceId(NSString *value) {
    if (value.length == 0) return;
    NSDictionary *del = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"LineAccount.DeviceId",
        (__bridge id)kSecAttrAccount: @"client",
    };
    SecItemDelete((__bridge CFDictionaryRef)del);
    NSDictionary *add = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"LineAccount.DeviceId",
        (__bridge id)kSecAttrAccount: @"client",
        (__bridge id)kSecValueData: [value dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    };
    OSStatus st = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
    if (st == errSecDuplicateItem) {
        // 删除没生效却又重复 → 改用 update 覆盖数据
        NSDictionary *upd = @{ (__bridge id)kSecValueData: [value dataUsingEncoding:NSUTF8StringEncoding] };
        st = SecItemUpdate((__bridge CFDictionaryRef)del, (__bridge CFDictionaryRef)upd);
    }
    if (st != errSecSuccess) {
        NSLog(@"[LineAccount] kcWriteDeviceId 写 keychain 失败 st=%d（已有文件副本兜底）", (int)st);
    }
}

// uuid = NSUUID + 首次启动时间戳（持久化在 Keychain）
static NSString *deviceClientUUID(void) {
    static NSString *cached = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // ★ 文件为唯一真源：新手机首次运行生成一次并写入文件，之后不管用哪个号，
        //   都只从这个设备级文件读取（Library/LineSlots/.device_id，不在账号交换集、
        //   所有槽共用、不受锁屏/keychain 搬家影响）。keychain 仅作跨重装的次要备份。
        NSString *fromFile = fileReadDeviceId();
        if (fromFile.length > 0) {
            cached = fromFile;
        } else {
            // 文件还没有：老设备可能 keychain 里有旧值 → 拿来复用；否则全新生成
            NSString *fromKC = kcReadDeviceId();
            if (fromKC.length > 0) {
                cached = fromKC;
                NSLog(@"[LineAccount] uuid 从 keychain 迁移到文件=%@", cached);
            } else {
                NSString *u = [[NSUUID UUID] UUIDString];
                long long ts = (long long)[[NSDate date] timeIntervalSince1970];
                cached = [NSString stringWithFormat:@"%@_%lld", u, ts];
                NSLog(@"[LineAccount] 新设备 uuid=%@", cached);
            }
            fileWriteDeviceId(cached);   // 一律落文件，成为唯一真源
            kcWriteDeviceId(cached);     // keychain 备份（可跨重装恢复）
        }
    });
    return cached;
}

static LARemoteAccount *accountForSlot(NSInteger slot) {
    @synchronized ([LARemoteAccount class]) {
        for (LARemoteAccount *a in g_remoteAccounts) {
            if (a.slot == slot) return a;
        }
        return nil;
    }
}

static NSArray<LARemoteAccount *> *parseAccountsJSON(id root) {
    NSArray *arr = nil;
    if ([root isKindOfClass:[NSDictionary class]]) {
        id a = root[@"accounts"] ?: root[@"data"] ?: root[@"list"];
        if ([a isKindOfClass:[NSArray class]]) arr = a;
    } else if ([root isKindOfClass:[NSArray class]]) {
        arr = (NSArray *)root;
    }
    if (arr.count == 0) return @[];

    NSMutableArray *out = [NSMutableArray array];
    for (id item in arr) {
        if (![item isKindOfClass:[NSDictionary class]]) continue;
        NSDictionary *d = (NSDictionary *)item;
        LARemoteAccount *acc = [LARemoteAccount new];
        // ★ 绑定后端主键 Id（唯一、不变、不复用）→ 本地存储 account_<Id> 永远稳定，
        //   slot 列随便你在数据库改/排序/显示都不影响存储。兜底才用 slot。
        acc.slot = [d[@"Id"] integerValue];
        if (acc.slot < 1) acc.slot = [d[@"slot"] integerValue];
        if (acc.slot < 1 || acc.slot > ACCOUNT_COUNT) continue;
        acc.name = [NSString stringWithFormat:@"%@", d[@"name"] ?: d[@"title"] ?: [NSString stringWithFormat:@"账号%ld", (long)acc.slot]];
        id proxy = d[@"proxy"];
        NSDictionary *p = [proxy isKindOfClass:[NSDictionary class]] ? proxy : d;
        acc.proxyHost = [NSString stringWithFormat:@"%@", p[@"host"] ?: p[@"ip"] ?: @""];
        acc.proxyPort = [NSString stringWithFormat:@"%@", p[@"port"] ?: @""];
        acc.proxyUser = [NSString stringWithFormat:@"%@", p[@"user"] ?: p[@"username"] ?: @""];
        acc.proxyPass = [NSString stringWithFormat:@"%@", p[@"pass"] ?: p[@"password"] ?: @""];
        acc.proxyType = [[NSString stringWithFormat:@"%@", p[@"type"] ?: @"http"] lowercaseString];
        if (acc.proxyHost.length == 0 || acc.proxyPort.length == 0) {
            // 允许无代理（直连），仍显示账号
            acc.proxyHost = nil;
            acc.proxyPort = nil;
        }
        [out addObject:acc];
    }
    // 不在此重排：保持后端 PHP 返回的顺序（后端已按需排好）
    return out;
}

static void applyRemoteAccounts(NSArray<LARemoteAccount *> *list) {
    @synchronized ([LARemoteAccount class]) {
        g_remoteAccounts = [list copy] ?: @[];
    }
    la_invalidateProxyCache();
    // 只有 1 个账号时，选择页阶段也预先挂这个槽的代理（避免 legy 先直连）
    if (g_remoteAccounts.count == 1) {
        la_setProxyActiveSlot(g_remoteAccounts.firstObject.slot);
    }
    NSLog(@"[LineAccount] 远程账号 %lu 个 activeProxySlot=%ld",
          (unsigned long)g_remoteAccounts.count, (long)g_proxyActiveSlot);
}

static BOOL loadRemoteAccountsFromCache(void) {
    NSData *data = [NSData dataWithContentsOfFile:remoteConfigCachePath()];
    if (data.length == 0) return NO;
    id root = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    NSArray *list = parseAccountsJSON(root);
    if (list.count == 0) return NO;
    applyRemoteAccounts(list);
    return YES;
}

static void saveRemoteAccountsCache(NSData *data) {
    if (data.length == 0) return;
    mkdirp(slotsRootPath());
    [data writeToFile:remoteConfigCachePath() atomically:YES];
}

// 异步拉取；completion 在主线程。失败时尽量用缓存。
static void fetchRemoteAccounts(void (^completion)(BOOL ok, NSString *err)) {
    NSString *uuid = deviceClientUUID() ?: @"unknown";
    NSString *urlStr = [NSString stringWithFormat:@"%@?uuid=%@",
                        LA_CONFIG_API_BASE,
                        [uuid stringByAddingPercentEncodingWithAllowedCharacters:
                         [NSCharacterSet URLQueryAllowedCharacterSet]]];
    NSURL *url = [NSURL URLWithString:urlStr];
    NSLog(@"[LineAccount] 拉取配置 %@", urlStr);

    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    cfg.timeoutIntervalForRequest = 12;
    cfg.connectionProxyDictionary = @{}; // 拉配置本身绝不走代理
    NSURLSession *session = [NSURLSession sessionWithConfiguration:cfg];
    [[session dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *resp, NSError *error) {
        void (^done)(BOOL, NSString *) = ^(BOOL ok, NSString *err) {
            dispatch_async(dispatch_get_main_queue(), ^{
                g_remoteFetchDone = YES;
                g_remoteFetchError = err;
                if (completion) completion(ok, err);
            });
        };
        if (error || data.length == 0) {
            NSString *msg = error.localizedDescription ?: @"空响应";
            NSLog(@"[LineAccount] 拉取失败(将尝试缓存): %@", msg);
            if (loadRemoteAccountsFromCache()) {
                done(YES, @"cache");   // 第二选择：缓存
            } else {
                done(NO, msg);
            }
            return;
        }
        // 落盘原始响应，方便 Frida/电脑直接看服务器到底回了啥
        {
            mkdirp(slotsRootPath());
            NSString *dumpPath = [slotsRootPath() stringByAppendingPathComponent:@".remote_last_response.txt"];
            NSString *body = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]
                          ?: [NSString stringWithFormat:@"<binary %lu bytes>", (unsigned long)data.length];
            [body writeToFile:dumpPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
            NSLog(@"[LineAccount] 配置响应 %lu 字节 头: %@",
                  (unsigned long)data.length,
                  body.length > 200 ? [body substringToIndex:200] : body);
        }
        id root = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        NSArray *list = parseAccountsJSON(root);
        if (list.count == 0) {
            NSString *body = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"";
            NSLog(@"[LineAccount] JSON 无账号(解析失败或空列表) body=%@", body);
            if (loadRemoteAccountsFromCache()) {
                done(YES, @"cache");
            } else {
                done(NO, @"远端未返回账号");
            }
            return;
        }
        saveRemoteAccountsCache(data);
        applyRemoteAccounts(list);
        done(YES, nil);
    }] resume];
}

#pragma mark - 账号选择 UI

static void enterAccountSlot(NSInteger slot);
static void clearAccountSlot(NSInteger slot);
static NSInteger readCurrentSlot(void);
static NSInteger readPending(void);

#pragma mark - 屏上日志（沙盒无法写系统 CrashReporter，直接在选择页里看）

@interface LALogViewController : UIViewController
@property(nonatomic, strong) UITextView *tv;
@end

static NSMutableArray<NSString *> *g_laLogLines = nil;

// 线程安全追加一条日志（la_flog 每写一行就调用），内存里最多留 1000 行
static void laAppendLogLine(NSString *rec) {
    if (!rec) return;
    @synchronized([LALogViewController class]) {
        if (!g_laLogLines) g_laLogLines = [NSMutableArray array];
        [g_laLogLines addObject:rec];
        NSInteger over = (NSInteger)g_laLogLines.count - 1000;
        if (over > 0) [g_laLogLines removeObjectsInRange:NSMakeRange(0, over)];
    }
}

// 汇总日志文本。★ 优先读持久化的 proxy.log（跨重启存活），这样 KakaoTalk 迁移 forceQuit+relaunch
//   后仍能看到上一次启动切号时的 [sw] 记录；内存缓冲只在磁盘读不到时兜底。
static NSString *laRecentLogText(void) {
    NSMutableString *s = [NSMutableString string];
    NSString *cpath = [slotsRootPath() stringByAppendingPathComponent:@"proxy.log"];
    NSString *disk = [NSString stringWithContentsOfFile:cpath encoding:NSUTF8StringEncoding error:nil];
    if (disk.length) {
        // 只保留尾部 ~240KB，避免查看器卡（历史很长时看最近的即可）
        const NSUInteger kMax = 240 * 1024;
        if (disk.length > kMax) disk = [disk substringFromIndex:disk.length - kMax];
        [s appendString:disk];
    }
    if (s.length == 0) {
        @synchronized([LALogViewController class]) {
            for (NSString *l in g_laLogLines) [s appendString:l];
        }
    }
    if (s.length == 0) {
        [s appendString:@"（暂无日志）\n\n等 KakaoTalk 在后台联网 / 登录后，\n这里会实时出现记录。\n点右上角「刷新」更新。\n"];
    }
    return s;
}

@implementation LALogViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.blackColor;

    UITextView *tv = [[UITextView alloc] initWithFrame:CGRectZero];
    tv.translatesAutoresizingMaskIntoConstraints = NO;
    tv.editable = NO;
    tv.backgroundColor = UIColor.blackColor;
    tv.textColor = [UIColor colorWithRed:0.2 green:1.0 blue:0.35 alpha:1.0];
    tv.font = [UIFont fontWithName:@"Menlo" size:11] ?: [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    self.tv = tv;
    [self.view addSubview:tv];

    UIButton *close   = [self barButton:@"关闭"   sel:@selector(onClose)];
    UIButton *refresh = [self barButton:@"刷新"   sel:@selector(reload)];
    UIButton *copy    = [self barButton:@"复制全部" sel:@selector(onCopy)];
    UIButton *clear   = [self barButton:@"清空"   sel:@selector(onClear)];
    UILabel  *title   = [[UILabel alloc] init];
    title.text = @"代理连接日志";
    title.textColor = UIColor.whiteColor;
    title.font = [UIFont boldSystemFontOfSize:15];
    title.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:title];

    [NSLayoutConstraint activateConstraints:@[
        [title.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:16],
        [title.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor constant:12],

        [close.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-14],
        [close.centerYAnchor constraintEqualToAnchor:title.centerYAnchor],
        [refresh.trailingAnchor constraintEqualToAnchor:close.leadingAnchor constant:-10],
        [refresh.centerYAnchor constraintEqualToAnchor:title.centerYAnchor],
        [copy.trailingAnchor constraintEqualToAnchor:refresh.leadingAnchor constant:-10],
        [copy.centerYAnchor constraintEqualToAnchor:title.centerYAnchor],
        [clear.trailingAnchor constraintEqualToAnchor:copy.leadingAnchor constant:-10],
        [clear.centerYAnchor constraintEqualToAnchor:title.centerYAnchor],

        [tv.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:10],
        [tv.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:8],
        [tv.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-8],
        [tv.bottomAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor constant:-8],
    ]];

    [self reload];
}

- (UIButton *)barButton:(NSString *)t sel:(SEL)s {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    [b setTitle:t forState:UIControlStateNormal];
    [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont systemFontOfSize:14];
    b.backgroundColor = [UIColor colorWithWhite:1 alpha:0.18];
    b.layer.cornerRadius = 7;
    b.contentEdgeInsets = UIEdgeInsetsMake(5, 10, 5, 10);
    b.translatesAutoresizingMaskIntoConstraints = NO;
    [b addTarget:self action:s forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:b];
    return b;
}

- (void)reload {
    self.tv.text = laRecentLogText();
    NSUInteger len = self.tv.text.length;
    if (len > 0) [self.tv scrollRangeToVisible:NSMakeRange(len - 1, 1)];
}

- (void)onClose { [self dismissViewControllerAnimated:YES completion:nil]; }

- (void)onClear {
    UIAlertController *c = [UIAlertController alertControllerWithTitle:@"清空日志？"
        message:@"清除屏上缓冲与持久化 proxy.log 的全部记录（不影响账号数据）"
        preferredStyle:UIAlertControllerStyleAlert];
    [c addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [c addAction:[UIAlertAction actionWithTitle:@"清空" style:UIAlertActionStyleDestructive
                                        handler:^(UIAlertAction *a) {
        @synchronized([LALogViewController class]) { [g_laLogLines removeAllObjects]; }
        // 用 POSIX 直删，绕开被 hook 的 NSFileManager；proxy.log 在 slots 根(不参与搬运)
        removePathPOSIX([slotsRootPath() stringByAppendingPathComponent:@"proxy.log"]);
        [self reload];
    }]];
    [self presentViewController:c animated:YES completion:nil];
}

- (void)onCopy {
    UIPasteboard.generalPasteboard.string = self.tv.text ?: @"";
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"已复制"
                                                              message:@"日志已复制到剪贴板"
                                                       preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}

@end

@interface LineAccountPickerController : UIViewController
@property(nonatomic, strong) UIScrollView *scroll;
@property(nonatomic, strong) UIStackView *stack;
@property(nonatomic, strong) UILabel *statusLabel;
@property(nonatomic, weak)   UIButton *lastSelectedButton; // 上次选的号（红底+居中）
@property(nonatomic, assign) BOOL didCenterOnLast;         // 只自动居中一次
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

    // 右上角「日志」按钮：屏上直看代理连接日志（无需 SSH / 分析数据）
    UIButton *logBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [logBtn setTitle:@"日志" forState:UIControlStateNormal];
    [logBtn setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    logBtn.titleLabel.font = [UIFont boldSystemFontOfSize:15];
    logBtn.backgroundColor = [UIColor colorWithWhite:0 alpha:0.28];
    logBtn.layer.cornerRadius = 8;
    logBtn.contentEdgeInsets = UIEdgeInsetsMake(6, 14, 6, 14);
    logBtn.translatesAutoresizingMaskIntoConstraints = NO;
    [logBtn addTarget:self action:@selector(onShowLog) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:logBtn];
    [NSLayoutConstraint activateConstraints:@[
        [logBtn.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor constant:12],
        [logBtn.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-16],
    ]];

    UILabel *sub = [[UILabel alloc] initWithFrame:CGRectZero];
    sub.text = @"点选进入；长按可看代理 IP";
    sub.textColor = [UIColor colorWithWhite:1 alpha:0.85];
    sub.font = [UIFont systemFontOfSize:14];
    sub.textAlignment = NSTextAlignmentCenter;
    sub.numberOfLines = 2;
    sub.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:sub];

    self.statusLabel = [[UILabel alloc] initWithFrame:CGRectZero];
    self.statusLabel.text = @"正在拉取账号配置…";
    self.statusLabel.textColor = [UIColor colorWithWhite:1 alpha:0.9];
    self.statusLabel.font = [UIFont systemFontOfSize:13];
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.numberOfLines = 3;
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.statusLabel];

    // 账号多时需要滚动：stack 放进 scrollView，而不是直接钉在 view 上
    self.scroll = [[UIScrollView alloc] init];
    self.scroll.translatesAutoresizingMaskIntoConstraints = NO;
    self.scroll.showsVerticalScrollIndicator = YES;
    self.scroll.alwaysBounceVertical = YES;
    if (@available(iOS 11.0, *)) {
        self.scroll.contentInsetAdjustmentBehavior = UIScrollViewContentInsetAdjustmentNever;
    }
    [self.view addSubview:self.scroll];

    self.stack = [[UIStackView alloc] init];
    self.stack.axis = UILayoutConstraintAxisVertical;
    self.stack.spacing = 14;
    self.stack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.scroll addSubview:self.stack];

    [NSLayoutConstraint activateConstraints:@[
        [title.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor constant:48],
        [title.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:24],
        [title.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-24],
        [sub.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:8],
        [sub.leadingAnchor constraintEqualToAnchor:title.leadingAnchor],
        [sub.trailingAnchor constraintEqualToAnchor:title.trailingAnchor],
        [self.statusLabel.topAnchor constraintEqualToAnchor:sub.bottomAnchor constant:12],
        [self.statusLabel.leadingAnchor constraintEqualToAnchor:title.leadingAnchor],
        [self.statusLabel.trailingAnchor constraintEqualToAnchor:title.trailingAnchor],

        // scrollView：从状态标签下方一直到屏幕底部
        [self.scroll.topAnchor constraintEqualToAnchor:self.statusLabel.bottomAnchor constant:20],
        [self.scroll.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [self.scroll.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [self.scroll.bottomAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor constant:-16],

        // stack 钉在 scroll 的 content 区（决定 contentSize）
        [self.stack.topAnchor constraintEqualToAnchor:self.scroll.contentLayoutGuide.topAnchor constant:4],
        [self.stack.bottomAnchor constraintEqualToAnchor:self.scroll.contentLayoutGuide.bottomAnchor constant:-4],
        [self.stack.leadingAnchor constraintEqualToAnchor:self.scroll.contentLayoutGuide.leadingAnchor constant:32],
        [self.stack.trailingAnchor constraintEqualToAnchor:self.scroll.contentLayoutGuide.trailingAnchor constant:-32],
        // 锁定宽度 = 可视宽度 - 64，保证只纵向滚动
        [self.stack.widthAnchor constraintEqualToAnchor:self.scroll.frameLayoutGuide.widthAnchor constant:-64],
    ]];

    // 网络优先：先等拉取；失败再落缓存。不在这里抢先用缓存填列表（避免看起来像缓存优先）
    self.statusLabel.text = @"正在拉取账号配置…";
    __weak typeof(self) weakSelf = self;
    fetchRemoteAccounts(^(BOOL ok, NSString *err) {
        __strong typeof(weakSelf) self = weakSelf;
        if (!self) return;
        if (ok) {
            [self rebuildButtons];
            if ([err isEqualToString:@"cache"]) {
                // 网络失败后的第二选择
                self.statusLabel.text = [NSString stringWithFormat:@"共 %lu 个账号（离线缓存）",
                                        (unsigned long)g_remoteAccounts.count];
            } else {
                self.statusLabel.text = [NSString stringWithFormat:@"共 %lu 个账号",
                                        (unsigned long)g_remoteAccounts.count];
            }
        } else {
            self.statusLabel.text = [NSString stringWithFormat:@"配置失败：%@\n请检查网络后重开 LINE", err ?: @"未知错误"];
            if (g_remoteAccounts.count == 0) [self rebuildButtons];
        }
    });
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    if (self.didCenterOnLast) return;
    UIButton *b = self.lastSelectedButton;
    if (!b || !self.scroll) return;
    [self.scroll layoutIfNeeded];
    CGFloat visible = self.scroll.bounds.size.height;
    CGFloat content = self.scroll.contentSize.height;
    if (visible <= 0 || content <= 0) return;   // 布局还没就绪，下一轮再试
    CGRect f = [b convertRect:b.bounds toView:self.scroll];
    CGFloat maxOff = MAX(0, content - visible);
    CGFloat target = CGRectGetMidY(f) - visible / 2.0;   // 让按钮中心落在可视区中间
    target = MAX(0, MIN(target, maxOff));
    [self.scroll setContentOffset:CGPointMake(0, target) animated:NO];
    self.didCenterOnLast = YES;
}

- (void)rebuildButtons {
    for (UIView *v in [self.stack.arrangedSubviews copy]) {
        [self.stack removeArrangedSubview:v];
        [v removeFromSuperview];
    }
    self.lastSelectedButton = nil;
    self.didCenterOnLast = NO;
    // 上次选择的槽（.pending 每次选号都会写；兜底用 .current）
    NSInteger lastSlot = readPending();
    if (lastSlot < 1) lastSlot = readCurrentSlot();
    for (LARemoteAccount *acc in g_remoteAccounts) {
        UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
        NSString *flag = [slotHomePath(acc.slot) stringByAppendingPathComponent:@".used"];
        BOOL hasData = [[NSFileManager defaultManager] fileExistsAtPath:flag];
        BOOL isLast = (acc.slot == lastSlot);
        // 主页只显示名字（+ 标记）；ID 改到长按里看
        NSString *title = [NSString stringWithFormat:@"%@%@%@",
                           acc.name,
                           hasData ? @"  ·  已有数据" : @"",
                           isLast ? @"  ·  上次" : @""];
        [btn setTitle:title forState:UIControlStateNormal];
        btn.titleLabel.font = [UIFont boldSystemFontOfSize:18];
        if (isLast) {
            // 上次选的号：红底白字
            [btn setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
            btn.backgroundColor = [UIColor colorWithRed:0.85 green:0.16 blue:0.16 alpha:1.0];
            self.lastSelectedButton = btn;
        } else {
            [btn setTitleColor:[UIColor colorWithRed:0.06 green:0.45 blue:0.25 alpha:1.0]
                      forState:UIControlStateNormal];
            btn.backgroundColor = UIColor.whiteColor;
        }
        btn.layer.cornerRadius = 12;
        btn.tag = acc.slot;
        btn.contentEdgeInsets = UIEdgeInsetsMake(16, 20, 16, 20);
        [btn addTarget:self action:@selector(onSelect:) forControlEvents:UIControlEventTouchUpInside];
        UILongPressGestureRecognizer *lp = [[UILongPressGestureRecognizer alloc]
                                            initWithTarget:self action:@selector(onLongPress:)];
        lp.minimumPressDuration = 0.45;
        [btn addGestureRecognizer:lp];
        [self.stack addArrangedSubview:btn];
    }
    if (g_remoteAccounts.count == 0) {
        UILabel *empty = [[UILabel alloc] init];
        empty.text = @"暂无账号";
        empty.textColor = UIColor.whiteColor;
        empty.textAlignment = NSTextAlignmentCenter;
        [self.stack addArrangedSubview:empty];
    }
}

- (void)onSelect:(UIButton *)sender {
    enterAccountSlot(sender.tag);
}

- (void)onShowLog {
    LALogViewController *vc = [LALogViewController new];
    vc.modalPresentationStyle = UIModalPresentationFullScreen;
    [self presentViewController:vc animated:YES completion:nil];
}

- (void)onLongPress:(UILongPressGestureRecognizer *)gr {
    if (gr.state != UIGestureRecognizerStateBegan) return;
    NSInteger slot = gr.view.tag;
    LARemoteAccount *acc = accountForSlot(slot);
    if (!acc) return;
    NSString *ipInfo;
    if (acc.proxyHost.length) {
        ipInfo = [NSString stringWithFormat:@"ID：%ld\n代理 IP：%@:%@\n类型：%@\n账号：%@",
                  (long)slot, acc.proxyHost, acc.proxyPort,
                  acc.proxyType.length ? acc.proxyType : @"http",
                  acc.proxyUser.length ? acc.proxyUser : @"(无)"];
    } else {
        ipInfo = [NSString stringWithFormat:@"ID：%ld\n未配置代理（直连）", (long)slot];
    }
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:acc.name
                                                                   message:ipInfo
                                                            preferredStyle:UIAlertControllerStyleAlert];
    __weak typeof(self) weakSelf = self;
    // 清空此账号：点了先弹二次确认（确认 / 取消），确认后才真正删除
    [alert addAction:[UIAlertAction actionWithTitle:@"清空此账号数据"
                                              style:UIAlertActionStyleDestructive
                                            handler:^(UIAlertAction *a1) {
        __strong typeof(weakSelf) sself = weakSelf;
        if (!sself) return;
        UIAlertController *confirm = [UIAlertController alertControllerWithTitle:@"确认清空？"
            message:[NSString stringWithFormat:
                     @"将删除「%@」(ID:%ld) 在本机的全部本地数据（登录态/聊天/凭证），不可恢复。清空后需重新登录。",
                     acc.name, (long)slot]
            preferredStyle:UIAlertControllerStyleAlert];
        [confirm addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
        [confirm addAction:[UIAlertAction actionWithTitle:@"确认清空"
                                                    style:UIAlertActionStyleDestructive
                                                  handler:^(UIAlertAction *a2) {
            clearAccountSlot(slot);
            UIAlertController *done = [UIAlertController alertControllerWithTitle:@"已清空"
                message:@"该账号本地数据已删除，请重新打开 LINE。"
                preferredStyle:UIAlertControllerStyleAlert];
            [done addAction:[UIAlertAction actionWithTitle:@"重开" style:UIAlertActionStyleDefault
                                                   handler:^(UIAlertAction *a3) { exit(0); }]];
            __strong typeof(weakSelf) s2 = weakSelf;
            [s2 presentViewController:done animated:YES completion:nil];
        }]];
        [sself presentViewController:confirm animated:YES completion:nil];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
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
        @".build", @".bundleprefs.plist", @".groupprefs.plist",   // ★ 我们自己的元数据/偏好存储，绝不能进文件交换集
    ]];
    for (NSString *name in listChildrenPOSIX(base)) {
        if ([skipTop containsObject:name]) continue;
        if ([name hasPrefix:@".gp."]) continue;   // ★ 按域存的 group 偏好文件(槽内元数据)，绝不进文件交换集
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
// ★ v15：.pending = 用户「上次选择的目标槽」。开机构造函数据此在「任何账号线程起来前」把
//   Home 摆成目标账号；切到不同账号只写 pending 然后重启，绝不 live-swap（不破坏会话、不污染）。
static NSInteger readPending(void) {
    NSString *s = [NSString stringWithContentsOfFile:swapStatePath(@".pending")
                                            encoding:NSUTF8StringEncoding error:nil];
    return s ? s.integerValue : 0;
}
static void writePending(NSInteger slot) {
    mkdirp(slotsRootPath());
    [[NSString stringWithFormat:@"%ld", (long)slot]
        writeToFile:swapStatePath(@".pending") atomically:YES
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
    int e1 = errno;
    // rename 失败(可能 EXDEV/EPERM/保护类不匹配)：退化为「复制+删源」，保证文件一定搬过去、数据不丢。
    NSError *cerr = nil;
    if ([[NSFileManager defaultManager] copyItemAtPath:src toPath:dst error:&cerr]) {
        removePathPOSIX(src);
        NSLog([NSString stringWithFormat:@"[LineAccount] SWAP rename→copy 退化 OK (errno=%d) %@ -> %@",
               e1, src, dst]);
        return YES;
    }
    NSLog([NSString stringWithFormat:@"[LineAccount] SWAP move FAIL errno=%d copyErr=%@ %@ -> %@",
           e1, cerr.localizedDescription ?: @"?", src, dst]);
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
    la_flog([NSString stringWithFormat:@"[sw] 文件 drained Home→slot %ld (%lu项)", (long)slot, (unsigned long)items.count]);
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
    la_flog([NSString stringWithFormat:@"[sw] 文件 filled slot %ld→Home (%lu项)", (long)slot, (unsigned long)items.count]);
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
    // ★ 关键：默认查询只返回「不可同步」项，会漏掉 kSecAttrSynchronizable=YES 的凭证
    //   （LINE 的部分 e2ee/auth 凭证是可同步的）→ 枚举为空 → 停放 changed=0 → 账号被清。
    //   必须显式 kSecAttrSynchronizableAny 才能拿全。
    NSDictionary *q = @{
        (__bridge id)kSecClass:             (__bridge id)klass,
        (__bridge id)kSecMatchLimit:        (__bridge id)kSecMatchLimitAll,
        (__bridge id)kSecReturnAttributes:  (__bridge id)kCFBooleanTrue,
        (__bridge id)kSecAttrSynchronizable:(__bridge id)kSecAttrSynchronizableAny,
        // ★ 致命修复：不加这条，枚举撞到「受 ACL 保护(需生物识别/密码)」的条目会同步弹授权框并阻塞，
        //   开机构造器里就会触发 → 20 秒启动看门狗 0x8BADF00D 杀进程。UISkip = 遇到需授权的项静默跳过、绝不弹框。
        (__bridge id)kSecUseAuthenticationUI:(__bridge id)kSecUseAuthenticationUISkip,
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
        // ★ 关键：改名/删除查询也必须带 SynchronizableAny，否则默认只匹配「不可同步」项，
        //   LINE 的 cte-<mid>(频道令牌)/部分 e2ee 是可同步的 → 匹配不到 → errSecItemNotFound
        //   被当成功 → 实际没搬走，残留在 Home → 下个账号带着它登录 → 看得到别人的群/聊天。
        (__bridge id)kSecAttrSynchronizable: (__bridge id)kSecAttrSynchronizableAny,
        // ★ 注意：kSecUseAuthenticationUISkip 只对 SecItemCopyMatching 合法；放进 SecItemUpdate/Delete
        //   查询会导致 errSecParam(-50) → 改名全失败 changed=0 → Keychain 整个不按账号搬 → 令牌/设备ID
        //   永远停在同一账号 → 切号后 DB(账号B)配令牌(账号A)不一致 → KakaoTalk 触发迁移弹「完全关闭重启」。
        //   故这里【绝不能】加 UISkip（枚举 kcAllItems 里加才是对的）。
    } mutableCopy];
    if (svce.length > 0) query[(__bridge id)kSecAttrService] = svce;

    NSDictionary *attrs = @{ (__bridge id)kSecAttrAccount: newAcct };
    SecItemUpdate_t up = kcUpdate();
    if (!up) return NO;
    OSStatus st = up((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attrs);
    if (st == errSecSuccess || st == errSecItemNotFound) return YES;
    if (st == errSecDuplicateItem) {
        // ★ 丢号修复：目标名已存在（多为上次残留未搬回）。
        //   旧逻辑删「源」保「陈旧目标」→ 会丢掉正在搬运的真凭证（尤其 fill 去前缀时
        //   源=账号真实凭证）→ 该账号掉登录。改为：删掉【陈旧的目标】，保留正在搬运的源，
        //   再重试改名，让「正在搬运的这条」赢。
        NSMutableDictionary *delTarget = [@{
            (__bridge id)kSecClass:               (__bridge id)klass,
            (__bridge id)kSecAttrAccount:         newAcct,
            (__bridge id)kSecAttrSynchronizable:  (__bridge id)kSecAttrSynchronizableAny,
            // ★ 同理：Delete 查询不能带 UISkip（只对 Copy 合法），否则 errSecParam。
        } mutableCopy];
        if (svce.length > 0) delTarget[(__bridge id)kSecAttrService] = svce;
        SecItemDelete_t del = kcDelete();
        if (del) del((__bridge CFDictionaryRef)delTarget);
        OSStatus st2 = up((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attrs);
        if (st2 == errSecSuccess || st2 == errSecItemNotFound) {
            NSLog(@"[LineAccount] KC dup 已解决：删陈旧目标后改名成功 %@ -> %@ svce=%@", oldAcct, newAcct, svce);
            return YES;
        }
        NSLog(@"[LineAccount] KC dup 处理失败 st2=%d acct=%@ -> %@ svce=%@", (int)st2, oldAcct, newAcct, svce);
        return NO;
    }
    NSLog(@"[LineAccount] KC rename FAIL st=%d acct=%@ -> %@ svce=%@", (int)st, oldAcct, newAcct, svce);
    // 把确切错误码打到屏上日志：-50=参数错(多为查询里混入非法键)，-34018=缺权限，-25308=需交互被拒。
    static int s_kcFailLogged = 0;
    if (s_kcFailLogged < 6) {   // 只记前几条，避免刷屏
        s_kcFailLogged++;
        la_flog([NSString stringWithFormat:@"[kc] rename FAIL st=%d acct=%@→%@", (int)st, oldAcct, newAcct]);
    }
    return NO;
}

// 用 (klass, oldSvc, account="") 定位「纯 service 定位、空账号」的项(如 Kakao SSO 令牌
// com.kakao.sdk.sso.key / com.kakao.sdk.sso.keychain.tokens)，把 service 改成 newSvc。
// 这类项没有 account，按账号前缀改名(kcRenameAccount)命不中 → 必须改 service 才能按槽隔离。
static BOOL kcRenameService(CFTypeRef klass, NSString *oldSvc, NSString *newSvc) {
    if (oldSvc.length == 0 || newSvc.length == 0 || [oldSvc isEqualToString:newSvc]) return YES;
    NSDictionary *query = @{
        (__bridge id)kSecClass:              (__bridge id)klass,
        (__bridge id)kSecAttrService:        oldSvc,
        (__bridge id)kSecAttrAccount:        @"",   // 只命中空账号项，避免误伤同 service 下带账号的项
        (__bridge id)kSecAttrSynchronizable: (__bridge id)kSecAttrSynchronizableAny,
    };
    NSDictionary *attrs = @{ (__bridge id)kSecAttrService: newSvc };
    SecItemUpdate_t up = kcUpdate();
    if (!up) return NO;
    OSStatus st = up((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attrs);
    if (st == errSecSuccess || st == errSecItemNotFound) return YES;
    if (st == errSecDuplicateItem) {
        NSDictionary *delT = @{
            (__bridge id)kSecClass:              (__bridge id)klass,
            (__bridge id)kSecAttrService:        newSvc,
            (__bridge id)kSecAttrAccount:        @"",
            (__bridge id)kSecAttrSynchronizable: (__bridge id)kSecAttrSynchronizableAny,
        };
        SecItemDelete_t del = kcDelete();
        if (del) del((__bridge CFDictionaryRef)delT);
        OSStatus st2 = up((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attrs);
        return (st2 == errSecSuccess || st2 == errSecItemNotFound);
    }
    NSLog(@"[LineAccount] KC svc rename FAIL st=%d %@ -> %@", (int)st, oldSvc, newSvc);
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

            // ★ 我们自己的记账项(如 LineAccount.DeviceId=设备 UUID)不是 LINE 的登录凭证，
            //   绝不能参与按槽搬家/改名，否则会被搬进旧槽找不回 → 每次切槽 UUID 都变。
            if (svce.length > 0 && [svce hasPrefix:@"LineAccount."]) continue;

            // ★★ 空账号项(纯 service 定位)：如 Kakao 账号 SDK 的单点登录令牌
            //   com.kakao.sdk.sso.key / com.kakao.sdk.sso.keychain.tokens(base64)。
            //   它们没有 account，按账号前缀改名命不中 → 之前被 `continue` 整个跳过 →
            //   永不随号搬 → 谁最后登录 SSO 就一直是谁的 → 任何号(含全新空号)一读 SSO 就串成那个号。
            //   解法：对空账号项改用「service 前缀」来 drain/fill，实现按槽隔离。
            if (acct.length == 0) {
                if (svce.length == 0) continue;
                if (addPrefix) {
                    if ([svce hasPrefix:@"line.slot."]) continue;   // 已停放(带任意槽前缀)
                    if (kcRenameService(klass, svce, [prefix stringByAppendingString:svce])) changed++;
                } else {
                    if (![svce hasPrefix:prefix]) continue;          // 只搬本槽的
                    if (kcRenameService(klass, svce, [svce substringFromIndex:prefix.length])) changed++;
                }
                continue;
            }

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
    la_flog([NSString stringWithFormat:@"[sw] KC %@ slot %ld changed=%d",
             addPrefix ? @"drain(加前缀)" : @"fill(去前缀)", (long)slot, changed]);
}

static void drainKeychainToSlot(NSInteger slot)  { keychainSwap(slot, YES); }
static void fillKeychainFromSlot(NSInteger slot) { keychainSwap(slot, NO); }

// ★ 只读诊断：开机把当前 Keychain 全部条目打进日志（class/service/account/accessGroup/sync），
//   用来定位 KakaoTalk 的 SQLCipher 密钥/登录令牌到底放在哪个 service + access group，
//   以便把按槽隔离精确覆盖到它（不再瞎猜）。account 只打长度，不泄露内容。
static void la_dump_keychain_once(void) {
    static BOOL done = NO;
    if (done) return; done = YES;
    CFTypeRef classes[] = { kSecClassGenericPassword, kSecClassInternetPassword };
    const char *cnames[] = { "genp", "inet" };
    int shown = 0;
    for (int ci = 0; ci < 2; ci++) {
        for (NSDictionary *it in kcAllItems(classes[ci])) {
            if (shown >= 120) break;
            shown++;
            NSString *svc = [it[(__bridge id)kSecAttrService] isKindOfClass:[NSString class]] ? it[(__bridge id)kSecAttrService] : @"";
            NSString *acct = [it[(__bridge id)kSecAttrAccount] isKindOfClass:[NSString class]] ? it[(__bridge id)kSecAttrAccount] : @"";
            NSString *grp = [it[(__bridge id)kSecAttrAccessGroup] isKindOfClass:[NSString class]] ? it[(__bridge id)kSecAttrAccessGroup] : @"";
            id sync = it[(__bridge id)kSecAttrSynchronizable];
            la_flog([NSString stringWithFormat:@"[kc] %s svc=%@ acct=%@(len%lu) grp=%@ sync=%@",
                     cnames[ci], svc, acct, (unsigned long)acct.length, grp, sync ?: @"0"]);
        }
    }
    la_flog([NSString stringWithFormat:@"[kc] dump 完成，共 %d 条", shown]);
}

#pragma mark - 偏好域交换（第③层：把 cfprefsd 共享 bundle 域按槽搬进/搬出，堵 mid 泄漏）

// mid 等登录态实际写在 cfprefsd 管理的共享 bundle 域(Library/Preferences/<bundleid>.plist)，
// 既不在 Home 文件交换集里、也不是删文件能清（cfprefsd 有内存缓存）。故用 CFPreferences API
// 把整个共享域「读出→存进槽→从共享域删除」(drain)、「从槽读出→写回共享域」(fill)。
// 走 CFPreferences API，cfprefsd 缓存一致；激活槽全程用原生共享域(=纯净重签版行为)。
static NSString *slotPrefsPath(NSInteger slot) {        // bundle 域(<bundleid>.plist)
    return [slotHomePath(slot) stringByAppendingPathComponent:@".bundleprefs.plist"];
}
static NSString *slotGroupPrefsPath(NSInteger slot) {   // App Group 域(group.com.linecorp.line)
    return [slotHomePath(slot) stringByAppendingPathComponent:@".groupprefs.plist"];
}

// ★ v11：App Group 偏好域(group.com.linecorp.line)也要按槽交换。
//   LINE 的 mid / 推送 / 设备注册 / 会话身份都写在这个域里，由 cfprefsd 存共享 group 容器，
//   既不在文件交换集、也不是 bundle 域 → v10 之前从没被交换 → 永远停在「最后登录的账号」。
//   于是回到另一账号时：凭证=A、group域身份=B → 服务端拒连 → 「网络连接发生错误 / 无法正常处理」。
#define LINE_GROUP_ID CFSTR("group.com.linecorp.line")

// ★ App Group 偏好域登记表：hooked_containerURL 把 App 实际用到的每个 group id 记这里，
//   存 slots 根(不参与文件搬运、跨账号切换存活)。偏好搬运时对所有 group 域逐个 drain/fill，
//   从而对 KakaoTalk 的 group.com.iwilab.KakaoTalk[.<team>] 及任何 App 的 group 自动隔离。
static NSString *la_appGroupsRegistryPath(void) { return swapStatePath(@".appgroups.plist"); }
static NSArray<NSString *> *la_recordedAppGroups(void) {
    NSArray *a = [NSArray arrayWithContentsOfFile:la_appGroupsRegistryPath()];
    return [a isKindOfClass:[NSArray class]] ? a : @[];
}
static void la_recordAppGroup(NSString *gid) {
    if (gid.length == 0) return;
    static NSLock *lock; static dispatch_once_t once;
    dispatch_once(&once, ^{ lock = [NSLock new]; });
    [lock lock];
    NSMutableArray *a = [la_recordedAppGroups() mutableCopy];
    if (![a containsObject:gid]) { [a addObject:gid]; [a writeToFile:la_appGroupsRegistryPath() atomically:YES]; }
    [lock unlock];
}
// 需要按槽搬运的所有 App Group 偏好域 = LINE 默认 ∪ 从 bundleId 派生(含/不含 team 后缀) ∪ 运行时登记表。
// 从 bundleId 派生可覆盖首次启动(登记表还空)且不惧重签换 team：
//   com.iwilab.KakaoTalk.9YV3UM7J6Z → group.com.iwilab.KakaoTalk.9YV3UM7J6Z + group.com.iwilab.KakaoTalk
static NSArray<NSString *> *la_groupDomainsToSwap(void) {
    NSMutableOrderedSet<NSString *> *s = [NSMutableOrderedSet orderedSet];
    [s addObject:@"group.com.linecorp.line"];
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    if (bid.length) {
        [s addObject:[@"group." stringByAppendingString:bid]];
        NSString *base = [bid stringByDeletingPathExtension];   // 去掉最后一段(重签 team 后缀)
        if (base.length && ![base isEqualToString:bid]) [s addObject:[@"group." stringByAppendingString:base]];
    }
    for (NSString *g in la_recordedAppGroups()) if (g.length) [s addObject:g];
    return [s array];
}
// 每个 group 域在槽内的存储文件（按域名生成，互不覆盖；文件名以 .gp. 打头，swapRelItemsUnder 会跳过）
static NSString *slotGroupPrefsPathForDomain(NSInteger slot, NSString *domain) {
    return [slotHomePath(slot) stringByAppendingPathComponent:
            [NSString stringWithFormat:@".gp.%@.plist", domain]];
}

// 通用：把某个偏好域整体「读出→存文件→从该域清空」
static int drainDomainToPath(CFStringRef app, NSString *path) {
    CFArrayRef keys = CFPreferencesCopyKeyList(app, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
    NSMutableDictionary *store = [NSMutableDictionary dictionary];
    int n = 0;
    if (keys) {
        CFIndex cnt = CFArrayGetCount(keys);
        for (CFIndex i = 0; i < cnt; i++) {
            CFStringRef k = (CFStringRef)CFArrayGetValueAtIndex(keys, i);
            if (!k) continue;
            CFPropertyListRef v = CFPreferencesCopyValue(k, app, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
            if (v) { store[(__bridge NSString *)k] = (__bridge id)v; CFRelease(v); }
            CFPreferencesSetValue(k, NULL, app, kCFPreferencesCurrentUser, kCFPreferencesAnyHost); // 从域删除
            n++;
        }
        CFRelease(keys);
    }
    if (store.count) {
        [store writeToFile:path atomically:YES];
    }
    // ★ 丢号修复：空域时【绝不】删除槽内已保存的偏好文件。
    //   中断自愈会二次 drain，此时 Home 域已被上一次 drain 清空 → 若删文件就会抹掉
    //   刚搬进槽的 mid/登录态 → 该账号下次直接掉到登录界面。空域一律视为「无新数据」，
    //   保留槽内原文件（同槽自己的数据，回填无污染）。
    CFPreferencesSynchronize(app, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
    return n;
}

// 通用：先清空该域(兜底防串号)，再把文件里的键值写回该域
static int fillDomainFromPath(CFStringRef app, NSString *path) {
    CFArrayRef ex = CFPreferencesCopyKeyList(app, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
    if (ex) {
        CFIndex c = CFArrayGetCount(ex);
        for (CFIndex i = 0; i < c; i++) {
            CFStringRef k = (CFStringRef)CFArrayGetValueAtIndex(ex, i);
            if (k) CFPreferencesSetValue(k, NULL, app, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
        }
        CFRelease(ex);
    }
    NSDictionary *store = [NSDictionary dictionaryWithContentsOfFile:path];
    int n = 0;
    for (NSString *k in store) {
        CFPreferencesSetValue((__bridge CFStringRef)k, (__bridge CFPropertyListRef)store[k],
                              app, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
        n++;
    }
    CFPreferencesSynchronize(app, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
    return n;
}

static void drainPrefsToSlot(NSInteger slot) {
    if (slot < 1) return;
    mkdirp(slotHomePath(slot));
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    int nb = 0, ng = 0;
    if (bid.length) nb = drainDomainToPath((__bridge CFStringRef)bid, slotPrefsPath(slot));
    // ★ 所有 App Group 偏好域逐个搬（KakaoTalk 的 group.com.iwilab.KakaoTalk[.team] 身份就在这里）
    NSArray<NSString *> *domains = la_groupDomainsToSwap();
    for (NSString *d in domains) {
        ng += drainDomainToPath((__bridge CFStringRef)d, slotGroupPrefsPathForDomain(slot, d));
    }
    NSLog(@"[LineAccount] PREF drained -> slot %ld (bundle %d keys, %lu group域 共 %d keys)",
          (long)slot, nb, (unsigned long)domains.count, ng);
    la_flog([NSString stringWithFormat:@"[sw] PREF drained→slot %ld: bundle %d键, %lu个group域共 %d键",
             (long)slot, nb, (unsigned long)domains.count, ng]);
}

static void fillPrefsFromSlot(NSInteger slot) {
    if (slot < 1) return;
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    int nb = 0, ng = 0;
    if (bid.length) nb = fillDomainFromPath((__bridge CFStringRef)bid, slotPrefsPath(slot));
    NSArray<NSString *> *domains = la_groupDomainsToSwap();
    for (NSString *d in domains) {
        ng += fillDomainFromPath((__bridge CFStringRef)d, slotGroupPrefsPathForDomain(slot, d));
    }
    NSLog(@"[LineAccount] PREF filled slot %ld -> (bundle %d keys, %lu group域 共 %d keys)",
          (long)slot, nb, (unsigned long)domains.count, ng);
    la_flog([NSString stringWithFormat:@"[sw] PREF filled slot %ld→Home: bundle %d键, %lu个group域共 %d键",
             (long)slot, nb, (unsigned long)domains.count, ng]);
}

#pragma mark - Home 归属章（跟着数据走的 owner 标记，交叉校验 .current）

// 盖在 Application Support 内（属于交换集）→ drain 时随数据搬进槽、fill 时随数据搬回 Home。
// 开机时读 Home 里的归属章即知「Home 现在到底属于哪个槽」，比外部 .current 更不易失配。
static NSString *homeOwnerStampPath(void) {
    return [[realHomePath() stringByAppendingPathComponent:@"Library/Application Support"]
            stringByAppendingPathComponent:@".line_owner_slot"];
}
static void writeHomeOwnerStamp(NSInteger slot) {
    mkdirp([homeOwnerStampPath() stringByDeletingLastPathComponent]);
    [[NSString stringWithFormat:@"%ld", (long)slot]
        writeToFile:homeOwnerStampPath() atomically:YES
           encoding:NSUTF8StringEncoding error:nil];
}
static NSInteger readHomeOwnerStamp(void) {
    NSString *s = [NSString stringWithContentsOfFile:homeOwnerStampPath()
                                            encoding:NSUTF8StringEncoding error:nil];
    return s ? s.integerValue : 0;
}

// 把「上一个 active 槽」的三层数据(文件+keychain+偏好)全部搬回它的槽，Home/keychain/共享偏好域归零。
// owner：优先用 Home 归属章(跟着数据走，最准)，退回 .current。
static void drainHomeAllLayers(NSInteger owner) {
    if (owner < 1) return;
    NSLog(@"[LineAccount] DRAIN-ALL 清空 Home -> slot %ld（文件+keychain+偏好）", (long)owner);
    writeJournal(owner, 0, @"drain");
    drainPrefsToSlot(owner);            // ③ 先搬偏好(mid)——它在共享域，独立于文件
    drainHomeToSlot(owner);             // ① 文件
    drainKeychainToSlot(owner);         // ② keychain
    writeCurrentSlot(0);
    clearJournal();
}

// 把「目标槽」的三层数据搬回 Home/keychain/共享偏好域，成为激活账号。
static void fillHomeAllLayers(NSInteger to) {
    if (to < 1) return;
    NSLog(@"[LineAccount] FILL-ALL slot %ld -> Home（文件+keychain+偏好）", (long)to);
    writeJournal(0, to, @"fill");
    fillHomeFromSlot(to);               // ① 文件
    fillKeychainFromSlot(to);           // ② keychain
    fillPrefsFromSlot(to);              // ③ 偏好(mid)
    writeHomeOwnerStamp(to);            // 盖归属章：Home 现在属于 to
    writeCurrentSlot(to);
    clearJournal();
}

// 切换到目标槽：先把上一个账号搬回它的槽(若 eager drain 已做则 from=0 跳过)，再把目标槽搬进 Home。
static void swapToSlot(NSInteger to) {
    if (to < 1 || to > ACCOUNT_COUNT) return;
    NSInteger from = readCurrentSlot();
    if (from == to) {
        NSLog(@"[LineAccount] SWAP same slot %ld，Home 数据原样保留（重开同账号）", (long)to);
        return;
    }
    NSLog(@"[LineAccount] SWAP %ld -> %ld begin", (long)from, (long)to);
    if (from >= 1) drainHomeAllLayers(from);   // 切到不同账号：先把旧号三层数据搬回它的槽
    fillHomeAllLayers(to);
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
        if (from >= 1) { drainPrefsToSlot(from); drainHomeToSlot(from); drainKeychainToSlot(from); }
        writeCurrentSlot(0);             // 停在「Home 空、数据在槽」，交给选择页重新决定
    } else { // fill
        fillHomeFromSlot(to);
        fillKeychainFromSlot(to);
        fillPrefsFromSlot(to);
        writeHomeOwnerStamp(to);
        writeCurrentSlot(to);
    }
    clearJournal();
    NSLog(@"[LineAccount] SWAP 自愈完成");
}

// ★ v12：不再开机 eager-drain。旧做法每次冷启动先把 Home 三层全清空搬进槽，
//   导致「重开同一个账号」也白白经历 Home→槽→Home 一整趟往返，破坏了 LINE 的会话恢复
//   （表现：第一次登录能聊/能发，第二次重启选同号就"无法正常处理/发不出"）。
//   改为「认领」：Home 里本来就放着上一个 active 账号的数据，只用归属章校正 .current。
//   这样重开同号时 swapToSlot 命中 from==to → 零搬运（完全等价纯净重签版重启）；
//   只有真正切到不同账号时，swapToSlot 才 drain 旧号 + fill 新号。
static void eagerAdoptAtBoot(void) {
    NSInteger stamp = readHomeOwnerStamp();
    NSInteger cur   = readCurrentSlot();
    if (stamp >= 1 && stamp != cur) {
        NSLog(@"[LineAccount] 开机认领：以归属章 slot %ld 校正 .current(%ld)", (long)stamp, (long)cur);
        writeCurrentSlot(stamp);   // 相信 Home 里实际数据的归属章
    } else {
        NSLog(@"[LineAccount] 开机认领：Home owner = slot %ld（数据原样保留，不搬运）",
              (long)(cur >= 1 ? cur : stamp));
    }
}

// ★ v14：重新启用开机 eager-drain —— 这是修复「切账号时数据污染」的关键。
//   实测(watch_switch)证明：在选择页停留并点账号时，LINE 从 +load/静态构造启动的后台线程
//   早已把「上一个 active 账号」的 mid 加载进内存；我们把三层数据搬走(drain→槽 / fill→新号)后，
//   这些仍活着的线程会立刻把旧账号的 cte-<mid>/P_<mid> 等重新写回 Home → 与新号数据混合
//   → LINE 判定「无法读取好友与聊天数据」并触发迁移/污染。
//   解法：在构造函数最早期(选择页出现前、任何账号被加载之前)就把 Home 三层清空到归属槽，
//   使选择页出现时 Home/keychain/共享偏好域全部白板 → 任何后台线程都读不到账号 → 不会写回。
//   之后选账号只需 fill(swapToSlot 命中 from(0)!=to → 只 fill)，全程不存在「活账号被搬」的窗口。
//   注：v12 曾因「重开同号往返破坏会话」而移除本函数，但那实为 v13 才修的 keychain 可同步项
//   丢失所致；三层修复后往返是无损的(rename 进出、内容不变)，同号重开可安全还原。
// ★ v15：开机对账——在选择页出现前、任何账号线程起来之前，把 Home 摆成「上次选择的目标槽」。
//   - 若 pending==owner(或无 pending)：原样保留 Home(=v13 行为，会话不坏)，只校正 .current。
//   - 若 pending!=owner：此刻没有任何账号被加载，安全地 drain 旧号 + fill 目标 → Home 成为目标账号。
//   关键：LINE 真正运行时，Home 从启动那一刻就是完整、一致的目标账号 → 不会「无法正常处理」；
//   且交换只发生在这里(无线程)→ 活线程绝不会把旧账号写回来污染。切不同账号靠「写 pending + 重启」。
static void reconcileTargetAtBoot(void) {
    NSInteger owner = readHomeOwnerStamp();
    if (owner < 1) owner = readCurrentSlot();
    NSInteger pending = readPending();

    if (pending >= 1 && pending != owner) {
        NSLog(@"[LineAccount] 开机换号：Home(owner %ld) -> 目标 slot %ld（线程未起，安全搬运）",
              (long)owner, (long)pending);
        la_flog([NSString stringWithFormat:@"[sw] 开机换号 owner=%ld -> slot=%ld（安全搬运）", (long)owner, (long)pending]);
        if (owner >= 1) drainHomeAllLayers(owner);   // 旧号三层搬回它的槽，Home 归零
        fillHomeAllLayers(pending);                  // 目标三层进 Home，current=stamp=pending
    } else {
        NSInteger cur = readCurrentSlot();
        if (owner >= 1 && cur != owner) writeCurrentSlot(owner);   // 认领：校正 .current
        NSLog(@"[LineAccount] 开机对账：Home owner = slot %ld，原样保留(会话完好)", (long)(owner >= 1 ? owner : 0));
        la_flog([NSString stringWithFormat:@"[sw] 开机对账 owner=%ld pending=%ld → 原样保留(不搬)", (long)owner, (long)pending]);
    }
}

// ★ v15：切到「不同账号」时，不做 live 交换(会破坏会话+污染)。写好 pending 后结束进程，
//   用户重开时 reconcileTargetAtBoot() 会在任何账号线程起来前把 Home 换成目标账号。
static void restartForAccountSwitch(NSInteger to) {
    NSLog(@"[LineAccount] 切到不同账号 slot %ld：写 pending 后重启（避免 live-swap 破坏会话/污染）", (long)to);
    writePending(to);
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            if (pickerWindow) {
                for (UIView *v in [pickerWindow.subviews copy]) [v removeFromSuperview];
                UILabel *tip = [[UILabel alloc] initWithFrame:pickerWindow.bounds];
                tip.numberOfLines = 0;
                tip.textAlignment = NSTextAlignmentCenter;
                tip.textColor = [UIColor whiteColor];
                tip.font = [UIFont boldSystemFontOfSize:20];
                tip.text = @"正在切换账号…\n请重新打开 LINE";
                [pickerWindow addSubview:tip];
            }
        } @catch (__unused NSException *e) {}
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.3 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ exit(0); });
    });
}

// —— 清空某账号本地数据（三层：文件 / keychain / 偏好）——
// 删除某槽停放的 keychain（account 以 line.slot.<slot>. 开头）
static void wipeSlotKeychain(NSInteger slot) {
    NSString *prefix = slotKeyPrefix(slot);   // line.slot.N.
    CFTypeRef classes[] = { kSecClassGenericPassword, kSecClassInternetPassword };
    SecItemDelete_t del = kcDelete();
    if (!del) return;
    for (int ci = 0; ci < 2; ci++) {
        for (NSDictionary *it in kcAllItems(classes[ci])) {
            id acctObj = it[(__bridge id)kSecAttrAccount];
            id svceObj = it[(__bridge id)kSecAttrService];
            NSString *acct = [acctObj isKindOfClass:[NSString class]] ? acctObj : nil;
            NSString *svce = [svceObj isKindOfClass:[NSString class]] ? svceObj : nil;
            // 本槽停放项：account 带前缀(常规项) 或 service 带前缀(空账号 SSO 项)
            BOOL acctMatch = [acct hasPrefix:prefix];
            BOOL svcMatch  = (acct.length == 0 && [svce hasPrefix:prefix]);
            if (!acctMatch && !svcMatch) continue;
            NSMutableDictionary *q = [@{
                (__bridge id)kSecClass:              (__bridge id)classes[ci],
                (__bridge id)kSecAttrSynchronizable: (__bridge id)kSecAttrSynchronizableAny,
            } mutableCopy];
            if (acct != nil) q[(__bridge id)kSecAttrAccount] = acct;
            if (svce.length > 0) q[(__bridge id)kSecAttrService] = svce;
            del((__bridge CFDictionaryRef)q);
        }
    }
}

// 删除当前激活(Home)的 keychain：无前缀且非我们自己的记账项(LineAccount.*，保住 DeviceId)
static void wipeActiveKeychain(void) {
    CFTypeRef classes[] = { kSecClassGenericPassword, kSecClassInternetPassword };
    SecItemDelete_t del = kcDelete();
    if (!del) return;
    for (int ci = 0; ci < 2; ci++) {
        for (NSDictionary *it in kcAllItems(classes[ci])) {
            id acctObj = it[(__bridge id)kSecAttrAccount];
            id svceObj = it[(__bridge id)kSecAttrService];
            NSString *acct = [acctObj isKindOfClass:[NSString class]] ? acctObj : nil;
            NSString *svce = [svceObj isKindOfClass:[NSString class]] ? svceObj : nil;
            if (svce.length > 0 && [svce hasPrefix:@"LineAccount."]) continue;  // DeviceId 等自家项，保留
            if (acct.length == 0) {
                // 空账号项(Kakao SSO 令牌等)：激活态删除=SSO 登出；带槽前缀的是别的槽停放的，不动。
                if (svce.length == 0 || [svce hasPrefix:@"line.slot."]) continue;
            } else {
                if ([acct hasPrefix:@"line.slot."]) continue;                   // 其他槽停放的，不动
            }
            NSMutableDictionary *q = [@{
                (__bridge id)kSecClass:              (__bridge id)classes[ci],
                (__bridge id)kSecAttrSynchronizable: (__bridge id)kSecAttrSynchronizableAny,
            } mutableCopy];
            if (acct != nil) q[(__bridge id)kSecAttrAccount] = acct;
            if (svce.length > 0) q[(__bridge id)kSecAttrService] = svce;
            del((__bridge CFDictionaryRef)q);
        }
    }
}

// 清空一个偏好域（把所有键置 NULL）
static void clearPrefDomain(CFStringRef app) {
    CFArrayRef keys = CFPreferencesCopyKeyList(app, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
    if (keys) {
        CFIndex c = CFArrayGetCount(keys);
        for (CFIndex i = 0; i < c; i++) {
            CFStringRef k = (CFStringRef)CFArrayGetValueAtIndex(keys, i);
            if (k) CFPreferencesSetValue(k, NULL, app, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
        }
        CFRelease(keys);
    }
    CFPreferencesSynchronize(app, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
}

static void clearAccountSlot(NSInteger slot) {
    if (slot < 1) return;
    NSInteger owner = readHomeOwnerStamp();
    if (owner < 1) owner = readCurrentSlot();
    BOOL activeInHome = (owner == slot);

    // 若该号当前正占着 Home（活账号）→ 先把 Home 三层清掉，等于本地登出
    if (activeInHome) {
        for (NSString *rel in swapRelItemsUnder(realHomePath())) {
            removePathPOSIX(homeRel(rel));
        }
        wipeActiveKeychain();
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
        if (bid.length) clearPrefDomain((__bridge CFStringRef)bid);
        for (NSString *d in la_groupDomainsToSwap()) clearPrefDomain((__bridge CFStringRef)d);
        writeCurrentSlot(0);
    }

    // 删该槽存储三层
    removePathPOSIX(slotHomePath(slot));         // ① 文件（含 .used/归属章等）
    wipeSlotKeychain(slot);                       // ② keychain line.slot.<slot>.*
    removePathPOSIX(slotPrefsPath(slot));         // ③ 偏好（bundle 域）
    for (NSString *d in la_groupDomainsToSwap())  // ③ 偏好（所有 group 域）
        removePathPOSIX(slotGroupPrefsPathForDomain(slot, d));
    removePathPOSIX(slotGroupPrefsPath(slot));    // 兼容旧版单文件

    NSLog(@"[LineAccount] 已清空账号 slot %ld（activeInHome=%d）", (long)slot, activeInHome);
}

static void enterAccountSlot(NSInteger slot) {
    if (slot < 1 || slot > ACCOUNT_COUNT) return;
    // 必须是后台下发的账号
    if (!accountForSlot(slot)) {
        NSLog(@"[LineAccount] slot %ld 不在远程配置中，忽略", (long)slot);
        return;
    }

    mkdirp(slotHomePath(slot));
    [[NSData data] writeToFile:[slotHomePath(slot) stringByAppendingPathComponent:@".used"] atomically:YES];

    // 仅用于 UI 上标记「已有数据」
    NSMutableDictionary *meta = loadMeta();
    meta[@"selectedSlot"] = @(slot);
    saveMeta(meta);

    // ★ v15：判断 Home 当前归属。切到「不同账号」绝不 live-swap（会破坏会话 + 活线程污染）；
    //   而是写 pending 后重启，交给下次开机 reconcileTargetAtBoot() 在无线程时把 Home 换成目标。
    NSInteger owner = readHomeOwnerStamp();
    if (owner < 1) owner = readCurrentSlot();
    if (owner >= 1 && owner != slot) {
        la_flog([NSString stringWithFormat:@"[sw] 选号 slot=%ld，但 Home owner=%ld → 写 pending 重启换号", (long)slot, (long)owner]);
        writePending(slot);
        restartForAccountSwitch(slot);   // 弹提示 → exit(0)；不放行 LINE
        return;
    }
    la_flog([NSString stringWithFormat:@"[sw] 选号 slot=%ld owner=%ld → 同号/全新，直接放行(不重启)", (long)slot, (long)owner]);

    g_selectedSlot = slot;   // Keychain 前缀 + NSUserDefaults suite 按此隔离
    la_setProxyActiveSlot(slot); // 代理槽与选中账号对齐
    writePending(slot);      // 记住本次选择，供下次开机对账
    NSLog(@"[LineAccount] selected slot %ld（owner=%ld）— 同号/全新，直接放行", (long)slot, (long)owner);

    // ★ 同号(owner==slot)或全新(owner<1)：Home 已是目标账号或为空，只需 fill(同号=no-op)，不存在活账号被搬。
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
    if (g_pickerShown) return;   // didFinishLaunching / scene:willConnect 可能都触发，只显示一次
    void (^present)(void) = ^{
        if (g_pickerShown && pickerWindow && !pickerWindow.hidden) return;
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
            // ★ 必须高于 UIWindowLevelAlert(2000)：否则 KakaoTalk 自己的「完全关闭并重启」系统弹框
            //   (在 Alert 级) 会盖住选择页 + 日志按钮，用户点不了 → 死锁。抬到 Alert+1000 稳压其上。
            //   我们自己的二次确认/账号详情弹框由 picker VC present，落在本窗口内，不受影响。
            pickerWindow.windowLevel = UIWindowLevelAlert + 1000;
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
    // ★ KakaoTalk：必须先让原生 didFinishLaunching 跑完（注册 Factory/DI 依赖），
    //   否则场景 willResignActive 时 resolve 未注册依赖会触发 Swift fatalError（brk 1）。
    //   启动完成后再把选择页作为高层覆盖窗口盖上去，不打断 KakaoTalk 生命周期。
    BOOL r = YES;
    if (orig_didFinishLaunching) {
        r = ((BOOL(*)(id,SEL,UIApplication*,NSDictionary*))orig_didFinishLaunching)(self, _cmd, app, opts);
    }
    if (g_needPicker && !g_launchResumed) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (g_needPicker && !g_launchResumed) showAccountPicker();
        });
    }
    return r;
}

static void hooked_sceneWillConnect(id self, SEL _cmd, UIScene *scene, UISceneSession *session, id opts) {
    // ★ KakaoTalk：先让原生 scene:willConnect 跑完（建立窗口 + 场景内 DI），
    //   再把选择页覆盖到同一场景上层。绝不再「挂起场景不建立」——那会让 KakaoTalk 的
    //   _UISceneLifecycleMonitor 在 willResignActive 里 resolve 未初始化依赖而 fatalError。
    if (orig_sceneWillConnect) {
        ((void(*)(id,SEL,UIScene*,UISceneSession*,id))orig_sceneWillConnect)(self, _cmd, scene, session, opts);
    }
    if (g_needPicker && !g_launchResumed) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (g_needPicker && !g_launchResumed) showAccountPicker();
        });
    }
}

// 从 Info.plist 的 UIApplicationSceneManifest 读出 scene delegate 类名（窗口角色）。
// ★ 关键：绝不调用 objc_copyClassList / objc_getClassList —— 那会强制 realize 进程内
//    所有类，在 iOS 26 arm64e 上触碰到 KakaoMapsSDK 等框架的只读方法列表会写崩（SIGBUS）。
static NSArray<NSString *> *sceneDelegateClassNamesFromPlist(void) {
    NSMutableArray *out = [NSMutableArray array];
    @try {
        NSDictionary *info = [[NSBundle mainBundle] infoDictionary];
        NSDictionary *manifest = info[@"UIApplicationSceneManifest"];
        NSDictionary *configs = manifest[@"UISceneConfigurations"];
        // 只取窗口角色（CarPlay 等 delegate 不响应 scene:willConnect: 也无所谓，避免多余 hook）
        id windowRole = configs[@"UIWindowSceneSessionRoleApplication"];
        NSArray *arr = [windowRole isKindOfClass:[NSArray class]] ? windowRole : nil;
        for (NSDictionary *cfg in arr) {
            NSString *cn = cfg[@"UISceneDelegateClassName"];
            if ([cn isKindOfClass:[NSString class]] && cn.length > 0) [out addObject:cn];
        }
    } @catch (__unused id e) {}
    return out;
}

static void hookSceneDelegates(void) {
    if (orig_sceneWillConnect) return;
    SEL sel = @selector(scene:willConnectToSession:options:);
    // 只按 Info.plist 里声明的 delegate 类名精确 hook，不枚举全表
    NSArray<NSString *> *names = sceneDelegateClassNamesFromPlist();
    for (NSString *name in names) {
        Class cls = NSClassFromString(name);   // Swift 类支持 "Module.Class" 形式
        if (!cls) {
            NSLog(@"[LineAccount] scene delegate 类未就绪: %@", name);
            continue;
        }
        Method m = ownInstanceMethod(cls, sel);
        if (!m) {
            NSLog(@"[LineAccount] %@ 无自有 scene:willConnect:，跳过", name);
            continue;
        }
        orig_sceneWillConnect = method_setImplementation(m, (IMP)hooked_sceneWillConnect);
        NSLog(@"[LineAccount] hooked scene:willConnect on %@", name);
        break; // 只 hook 一个
    }
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

#pragma mark - 每账号 HTTP 代理（方案 C：本地 CONNECT 中继 + 改写端点）

// Frida probe_proxyC 已验证：改写 legy/uts → 127.0.0.1 本地中继，再 HTTP CONNECT
// 上游代理。代理 host/port/user/pass 仍来自远程 JSON（按账号槽）。
// 方案 A（nw PAC）已弃用：prohibit=0 会直连，=1 不稳定。

typedef void *la_nw_object_t;
typedef la_nw_object_t (*la_nw_connection_create_fn)(la_nw_object_t endpoint, la_nw_object_t parameters);

static la_nw_connection_create_fn orig_nw_connection_create = NULL;

#include <os/lock.h>
#include <libkern/OSCacheControl.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif
static os_unfair_lock g_nwCreateLock = OS_UNFAIR_LOCK_INIT;
static void *g_nwCreateTarget = NULL;
static void *g_nwCreateTramp = NULL;
static uint8_t g_nwCreateSaved[16];
static uint8_t g_nwCreatePatch[16];
static BOOL g_nwCreateInlineReady = NO;
static BOOL g_nwCreateUseUnpatch = NO;

static la_nw_object_t (*p_nw_endpoint_create_host)(const char *, const char *) = NULL;
static const char *(*p_nw_endpoint_get_hostname)(la_nw_object_t) = NULL;
static uint16_t (*p_nw_endpoint_get_port)(la_nw_object_t) = NULL;
static BOOL g_endpointSPIReady = NO;
static int g_proxyHookEnterLogLeft = 16;

typedef struct {
    char host[256];
    uint16_t port;
    int32_t slot;
} la_pending_dest_t;

#define LA_PENDING_CAP 64
static la_pending_dest_t g_pending[LA_PENDING_CAP];
static int g_pending_r = 0, g_pending_w = 0, g_pending_n = 0;
static pthread_mutex_t g_pending_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_relay_listen_fd = -1;
static uint16_t g_relay_port = 0;
static BOOL g_relay_started = NO;

// ★ KakaoTalk 改造：侦察/免 frida
static int g_connLogLeft = 400;                 // proxy.log 侦察日志限量，防刷爆
static __thread int g_la_in_relay = 0;          // 中继自身出站连接：绕过 connect hook 防递归

// 文件日志。
// 目标：让日志出现在「设置→隐私与安全性→分析与改进→分析数据」列表里，
//       且文件名一眼能认出来 → 写到系统 CrashReporter 目录，固定名 KAKAO-PROXY-LOG.ips。
// 兜底：同时在 App 沙盒容器里留一份 proxy.log（万一沙盒禁止写系统目录）。
#define LA_ANALYTICS_LOG_NAME "KAKAO-PROXY-LOG.ips"

static BOOL la_append_file(const char *path, const char *bytes, size_t len) {
    if (!path || !bytes) return NO;
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return NO;
    (void)write(fd, bytes, len);
    close(fd);
    return YES;
}

// 网络日志静音总开关：YES=只留切号诊断([sw]/[boot]/[kc])与一次性横幅/错误，丢弃高频网络行。
// 想临时看网络流量：把 slotsRoot/.netlog 文件建出来即可（下方 laNetQuiet 读它）。
static BOOL laNetQuiet(void) {
    static int cached = -1;   // -1 未定；每次进程启动读一次标志文件
    if (cached < 0) {
        NSString *p = [slotsRootPath() stringByAppendingPathComponent:@".netlog"];
        cached = [[NSFileManager defaultManager] fileExistsAtPath:p] ? 0 : 1; // 有 .netlog=不安静
    }
    return cached == 1;
}
// 安静模式下是否应丢弃这行（高频网络类）。保留：[sw]/[boot]/[kc]、含“已装”的一次性横幅、代理错误行。
static BOOL laShouldDropWhenQuiet(NSString *line) {
    if ([line hasPrefix:@"[sw]"] || [line hasPrefix:@"[boot]"] || [line hasPrefix:@"[kc]"] || [line hasPrefix:@"[dbg]"]) return NO;
    if ([line rangeOfString:@"已装"].location != NSNotFound) return NO;      // 一次性安装横幅
    if ([line rangeOfString:@"失败"].location != NSNotFound) return NO;      // 错误保留
    if ([line rangeOfString:@"连不上"].location != NSNotFound) return NO;    // 错误保留
    if ([line rangeOfString:@"无代理"].location != NSNotFound) return NO;    // 异常保留
    if ([line hasPrefix:@"[url]"]  || [line hasPrefix:@"[grp]"] ||
        [line hasPrefix:@"[dns]"]  || [line hasPrefix:@"[connect]"] ||
        [line hasPrefix:@"[proxy]"]) return YES;                            // 高频网络行 → 丢
    return NO;
}

static void la_flog(NSString *line) {
    if (!line) return;
    if (laNetQuiet() && laShouldDropWhenQuiet(line)) return;   // ★ 静音：高频网络日志直接不写
    @autoreleasepool {
        NSString *rec = [NSString stringWithFormat:@"%.3f %@\n",
                         [[NSDate date] timeIntervalSince1970], line];
        laAppendLogLine(rec);   // ★ 同步进内存缓冲，供选择页「日志」窗口实时查看
        const char *b = rec.UTF8String;
        size_t blen = strlen(b);

        // 1) 系统 CrashReporter 目录（“分析数据”列表读的就是这里）。
        //    /var 是 /private/var 的符号链接，是同一文件 → 第一个成功就不再写第二个，避免重复。
        BOOL ok = la_append_file("/var/mobile/Library/Logs/CrashReporter/" LA_ANALYTICS_LOG_NAME, b, blen);
        if (!ok) {
            la_append_file("/private/var/mobile/Library/Logs/CrashReporter/" LA_ANALYTICS_LOG_NAME, b, blen);
        }

        // 2) 沙盒容器兜底一份
        NSString *cpath = [slotsRootPath() stringByAppendingPathComponent:@"proxy.log"];
        la_append_file(cpath.UTF8String, b, blen);

        NSLog(@"[LineAccount][flog] %@", line);
    }
}

// 是否把该 App 的“所有” TCP 连接都强制走本槽代理（LOCO 常按 IP 直连，域名过滤命不中时用）。
// 通过标志文件 slotsRoot/.relay_all 控制：存在=全量转发；不存在=只侦察记录不转发。
static BOOL laRelayAllTCP(void) {
    NSString *p = [slotsRootPath() stringByAppendingPathComponent:@".relay_all"];
    return [[NSFileManager defaultManager] fileExistsAtPath:p];
}

static void la_setProxyActiveSlot(NSInteger slot) {
    if (slot < 0) slot = 0;
    if (slot > ACCOUNT_COUNT) slot = 0;
    if (g_proxyActiveSlot == slot) return;
    g_proxyActiveSlot = slot;
    NSLog(@"[LineAccount][ProxyC] activeSlot -> %ld", (long)slot);
}

// 方案 C 无 PAC 对象缓存；远程 JSON 刷新后下次建连直接读 accountForSlot
static void la_invalidateProxyCache(void) {
    NSLog(@"[LineAccount][ProxyC] 远程账号已刷新，后续连接用新代理");
}

static BOOL la_proxyForceOff(void) {
    NSString *p = [slotsRootPath() stringByAppendingPathComponent:@".proxy_off"];
    return [[NSFileManager defaultManager] fileExistsAtPath:p];
}

static BOOL loadEndpointSPI(void) {
    if (g_endpointSPIReady) return YES;
    p_nw_endpoint_create_host = dlsym(RTLD_DEFAULT, "nw_endpoint_create_host");
    p_nw_endpoint_get_hostname = dlsym(RTLD_DEFAULT, "nw_endpoint_get_hostname");
    p_nw_endpoint_get_port = dlsym(RTLD_DEFAULT, "nw_endpoint_get_port");
    if (!p_nw_endpoint_create_host || !p_nw_endpoint_get_hostname || !p_nw_endpoint_get_port) {
        NSLog(@"[LineAccount][ProxyC] 缺 endpoint 符号 create=%p host=%p port=%p",
              p_nw_endpoint_create_host, p_nw_endpoint_get_hostname, p_nw_endpoint_get_port);
        return NO;
    }
    g_endpointSPIReady = YES;
    return YES;
}

static BOOL la_ascii_contains_ci(const char *hay, const char *needle) {
    if (!hay || !needle || !needle[0]) return NO;
    size_t nlen = strlen(needle);
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nlen) {
            char a = p[i], b = needle[i];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (!a || a != b) break;
            i++;
        }
        if (i == nlen) return YES;
    }
    return NO;
}

static BOOL la_host_should_relay(const char *h) {
    if (!h || !h[0]) return NO;
    if (strstr(h, "khpturuy.vip") != NULL) return NO;
    if (strcmp(h, "127.0.0.1") == 0 || strcmp(h, "localhost") == 0) return NO;
    // LINE 聊天主链路
    if (la_ascii_contains_ci(h, "legy")) return YES;
    if (la_ascii_contains_ci(h, "uts-front")) return YES;
    // KakaoTalk LOCO 主链路（booking-loco / ticket-loco / talk-pilsner / kage.talk / *.kakao.com）
    if (la_ascii_contains_ci(h, "loco")) return YES;
    if (la_ascii_contains_ci(h, "talk-pilsner")) return YES;
    if (la_ascii_contains_ci(h, "kage.talk")) return YES;
    if (la_ascii_contains_ci(h, ".kakao.com")) return YES;
    return NO;
}

static BOOL la_pending_push(const char *host, uint16_t port, NSInteger slot) {
    if (!host || !host[0] || port == 0) return NO;
    pthread_mutex_lock(&g_pending_mu);
    if (g_pending_n >= LA_PENDING_CAP) {
        pthread_mutex_unlock(&g_pending_mu);
        NSLog(@"[LineAccount][ProxyC] pending 队列满，丢弃 %s:%u", host, port);
        return NO;
    }
    la_pending_dest_t *d = &g_pending[g_pending_w];
    snprintf(d->host, sizeof(d->host), "%s", host);
    d->port = port;
    d->slot = (int32_t)slot;
    g_pending_w = (g_pending_w + 1) % LA_PENDING_CAP;
    g_pending_n++;
    pthread_mutex_unlock(&g_pending_mu);
    return YES;
}

static BOOL la_pending_pop(la_pending_dest_t *out) {
    pthread_mutex_lock(&g_pending_mu);
    if (g_pending_n <= 0) {
        pthread_mutex_unlock(&g_pending_mu);
        return NO;
    }
    *out = g_pending[g_pending_r];
    g_pending_r = (g_pending_r + 1) % LA_PENDING_CAP;
    g_pending_n--;
    pthread_mutex_unlock(&g_pending_mu);
    return YES;
}

#pragma mark - 方案 B：Swift 钩子回调的 C 接口（LineProxyHook-Bridging.h）

// 该 host 是否要走本地中继（legy / uts-front / LOCO）
bool la_host_should_relay_c(const char *host) {
    BOOL r = la_host_should_relay(host);
    // 侦察：记录每个 NWConnection(to:using:) 的目标 host → 判断 LOCO 是否走 NWConnection
    if (g_connLogLeft > 0) {
        g_connLogLeft--;
        la_flog([NSString stringWithFormat:@"[nwconn] host=%s relay=%d",
                 host ? host : "(null)", r ? 1 : 0]);
    }
    return r ? true : false;
}

// 登记真实目标到中继待处理队列
bool la_pending_push_c(const char *host, uint16_t port, int32_t slot) {
    return la_pending_push(host, port, (NSInteger)slot) ? true : false;
}

// 当前账号槽（选中优先，否则 activeSlot）
int32_t la_current_slot_c(void) {
    NSInteger s = (g_selectedSlot >= 1) ? g_selectedSlot : g_proxyActiveSlot;
    if (s < 0) s = 0;
    return (int32_t)s;
}

// 本地中继监听端口（0 = 未就绪）
uint16_t la_relay_port_c(void) {
    return g_relay_port;
}

// 是否强制关闭代理（.proxy_off 存在）
bool la_proxy_off_c(void) {
    return la_proxyForceOff() ? true : false;
}

static int la_send_all(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, p + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int la_tcp_connect_host(const char *host, int port, int timeout_sec) {
    if (!host || port <= 0) return -1;
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return -1;
    int fd = -1;
    g_la_in_relay = 1;   // ★ 本函数是中继自身出站，绕过 connect() hook 防递归
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        struct timeval tv;
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    g_la_in_relay = 0;   // ★
    freeaddrinfo(res);
    return fd;
}

static int la_http_connect_tunnel(int upfd, const char *destHost, uint16_t destPort,
                                  NSString *user, NSString *pass) {
    NSMutableString *req = [NSMutableString stringWithFormat:
                            @"CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\n",
                            destHost, destPort, destHost, destPort];
    if (user.length > 0) {
        NSString *token = [NSString stringWithFormat:@"%@:%@", user, pass ?: @""];
        NSData *raw = [token dataUsingEncoding:NSUTF8StringEncoding];
        NSString *b64 = [raw base64EncodedStringWithOptions:0];
        [req appendFormat:@"Proxy-Authorization: Basic %@\r\n", b64];
    }
    [req appendString:@"Proxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n\r\n"];
    NSData *reqData = [req dataUsingEncoding:NSUTF8StringEncoding];
    if (la_send_all(upfd, reqData.bytes, reqData.length) != 0) return -1;

    char buf[2048];
    size_t filled = 0;
    while (filled + 1 < sizeof(buf)) {
        ssize_t n = recv(upfd, buf + filled, sizeof(buf) - 1 - filled, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        filled += (size_t)n;
        buf[filled] = 0;
        if (strstr(buf, "\r\n\r\n")) break;
    }
    int code = 0;
    if (sscanf(buf, "HTTP/%*s %d", &code) != 1) return -1;
    return (code == 200) ? 0 : code;
}

static void la_pipe_one_way(int from, int to) {
    char buf[16384];
    while (1) {
        ssize_t n = recv(from, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        if (la_send_all(to, buf, (size_t)n) != 0) break;
    }
    shutdown(from, SHUT_RD);
    shutdown(to, SHUT_WR);
}

// ★ KakaoTalk：iOS 通过 connectionProxyDictionary 把请求发到本地中继，形式是标准 HTTP 代理协议：
//    HTTPS → "CONNECT host:port"；HTTP → 绝对形式 "GET http://host/... "。
//    中继解析出目标后，用与 LINE 相同的 la_http_connect_tunnel（CONNECT+Basic 认证）连上游代理。
static void la_relay_handle_http_proxy_client(int clientFd) {
    @autoreleasepool {
        char buf[8192];
        size_t filled = 0;
        while (filled + 1 < sizeof(buf)) {
            ssize_t n = recv(clientFd, buf + filled, sizeof(buf) - 1 - filled, 0);
            if (n < 0) { if (errno == EINTR) continue; close(clientFd); return; }
            if (n == 0) { close(clientFd); return; }
            filled += (size_t)n;
            buf[filled] = 0;
            if (strstr(buf, "\r\n\r\n")) break;
        }

        // 当前账号的上游代理
        NSInteger slot = (g_selectedSlot >= 1) ? g_selectedSlot : g_proxyActiveSlot;
        NSString *pHost = nil, *pPort = nil, *pUser = nil, *pPass = nil;
        @synchronized ([LARemoteAccount class]) {
            LARemoteAccount *acc = accountForSlot(slot);
            if (acc) { pHost = [acc.proxyHost copy]; pPort = [acc.proxyPort copy];
                       pUser = [acc.proxyUser copy]; pPass = [acc.proxyPass copy]; }
        }
        if (pHost.length == 0 || pPort.length == 0) {
            la_flog([NSString stringWithFormat:@"[proxy] slot=%ld 无代理→关连接", (long)slot]);
            close(clientFd); return;
        }
        int upfd = la_tcp_connect_host(pHost.UTF8String, pPort.intValue, 12);
        if (upfd < 0) {
            la_flog([NSString stringWithFormat:@"[proxy] 上游连不上 %@:%@", pHost, pPort]);
            close(clientFd); return;
        }

        if (strncmp(buf, "CONNECT ", 8) == 0) {
            char host[300] = {0}; int port = 443;
            if (sscanf(buf + 8, "%299[^: ]:%d", host, &port) < 1) { close(upfd); close(clientFd); return; }
            int cret = la_http_connect_tunnel(upfd, host, (uint16_t)port, pUser, pPass);
            if (cret != 0) {
                la_flog([NSString stringWithFormat:@"[proxy] CONNECT 失败 %s:%d via %@ code=%d", host, port, pHost, cret]);
                close(upfd); close(clientFd); return;
            }
            const char *ok = "HTTP/1.1 200 Connection established\r\n\r\n";
            if (la_send_all(clientFd, ok, strlen(ok)) != 0) { close(upfd); close(clientFd); return; }
            // 若 CONNECT 头后已带了数据（少见），先转给上游
            char *hdrEnd = strstr(buf, "\r\n\r\n");
            if (hdrEnd) { size_t hdrLen = (size_t)(hdrEnd - buf) + 4; if (filled > hdrLen) la_send_all(upfd, buf + hdrLen, filled - hdrLen); }
            if (g_connLogLeft > 0) { g_connLogLeft--; la_flog([NSString stringWithFormat:@"[proxy] TUNNEL %s:%d via %@:%@ slot=%ld", host, port, pHost, pPort, (long)slot]); }
        } else {
            // 绝对形式 HTTP：把首行后插入 Proxy-Authorization，再原样转发已读到的头
            char *eol = strstr(buf, "\r\n");
            if (!eol) { close(upfd); close(clientFd); return; }
            size_t lineLen = (size_t)(eol - buf) + 2;
            NSMutableData *out = [NSMutableData dataWithBytes:buf length:lineLen];
            if (pUser.length > 0) {
                NSString *token = [NSString stringWithFormat:@"%@:%@", pUser, pPass ?: @""];
                NSString *b64 = [[token dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
                NSString *h = [NSString stringWithFormat:@"Proxy-Authorization: Basic %@\r\n", b64];
                [out appendData:[h dataUsingEncoding:NSUTF8StringEncoding]];
            }
            [out appendBytes:buf + lineLen length:filled - lineLen];
            if (la_send_all(upfd, out.bytes, out.length) != 0) { close(upfd); close(clientFd); return; }
            if (g_connLogLeft > 0) { g_connLogLeft--; la_flog([NSString stringWithFormat:@"[proxy] HTTP via %@:%@ slot=%ld", pHost, pPort, (long)slot]); }
        }

        struct timeval tv0 = {0, 0};
        setsockopt(upfd, SOL_SOCKET, SO_SNDTIMEO, &tv0, sizeof(tv0));
        setsockopt(upfd, SOL_SOCKET, SO_RCVTIMEO, &tv0, sizeof(tv0));
        setsockopt(clientFd, SOL_SOCKET, SO_SNDTIMEO, &tv0, sizeof(tv0));
        setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO, &tv0, sizeof(tv0));

        dispatch_queue_t q = dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0);
        dispatch_group_t g = dispatch_group_create();
        dispatch_group_async(g, q, ^{ la_pipe_one_way(clientFd, upfd); });
        dispatch_group_async(g, q, ^{ la_pipe_one_way(upfd, clientFd); });
        dispatch_group_wait(g, DISPATCH_TIME_FOREVER);
        close(clientFd);
        close(upfd);
    }
}

static void la_relay_handle_client(int clientFd) {
    @autoreleasepool {
        la_pending_dest_t dest;
        if (!la_pending_pop(&dest)) {
            // pending 空 = 不是 LINE 的透明重定向，而是 KakaoTalk 经 connectionProxyDictionary 发来的标准代理请求
            la_relay_handle_http_proxy_client(clientFd);
            return;
        }

        // 拷贝代理字段，避免后台线程长时间持有 remote 对象
        NSString *pHost = nil, *pPort = nil, *pUser = nil, *pPass = nil;
        @synchronized ([LARemoteAccount class]) {
            LARemoteAccount *acc = accountForSlot(dest.slot);
            if (acc) {
                pHost = [acc.proxyHost copy];
                pPort = [acc.proxyPort copy];
                pUser = [acc.proxyUser copy];
                pPass = [acc.proxyPass copy];
            }
        }
        if (pHost.length == 0 || pPort.length == 0) {
            NSLog(@"[LineAccount][ProxyC] 槽%ld 无代理，关连接 %s:%u",
                  (long)dest.slot, dest.host, dest.port);
            close(clientFd);
            return;
        }

        int upPort = pPort.intValue;
        int upfd = la_tcp_connect_host(pHost.UTF8String, upPort, 12);
        if (upfd < 0) {
            NSLog(@"[LineAccount][ProxyC] 上游连失败 %@:%@ → %s:%u",
                  pHost, pPort, dest.host, dest.port);
            close(clientFd);
            return;
        }

        int cret = la_http_connect_tunnel(upfd, dest.host, dest.port, pUser, pPass);
        if (cret != 0) {
            NSLog(@"[LineAccount][ProxyC] CONNECT 失败 %s:%u via %@:%@ code=%d",
                  dest.host, dest.port, pHost, pPort, cret);
            close(upfd);
            close(clientFd);
            return;
        }

        if (g_proxyHookEnterLogLeft > 0) {
            g_proxyHookEnterLogLeft--;
            NSLog(@"[LineAccount][ProxyC] TUNNEL OK slot=%ld %s:%u via %@:%@ (logleft=%d)",
                  (long)dest.slot, dest.host, dest.port, pHost, pPort,
                  g_proxyHookEnterLogLeft);
        }

        struct timeval tv0 = {0, 0};
        setsockopt(upfd, SOL_SOCKET, SO_SNDTIMEO, &tv0, sizeof(tv0));
        setsockopt(upfd, SOL_SOCKET, SO_RCVTIMEO, &tv0, sizeof(tv0));
        setsockopt(clientFd, SOL_SOCKET, SO_SNDTIMEO, &tv0, sizeof(tv0));
        setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO, &tv0, sizeof(tv0));

        dispatch_queue_t q = dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0);
        dispatch_group_t g = dispatch_group_create();
        dispatch_group_async(g, q, ^{ la_pipe_one_way(clientFd, upfd); });
        dispatch_group_async(g, q, ^{ la_pipe_one_way(upfd, clientFd); });
        dispatch_group_wait(g, DISPATCH_TIME_FOREVER);
        close(clientFd);
        close(upfd);
    }
}

static BOOL la_start_local_relay(void) {
    if (g_relay_started && g_relay_port > 0) return YES;

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        NSLog(@"[LineAccount][ProxyC] socket 失败 errno=%d", errno);
        return NO;
    }
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        NSLog(@"[LineAccount][ProxyC] bind 失败 errno=%d", errno);
        close(fd);
        return NO;
    }
    if (listen(fd, 128) != 0) {
        NSLog(@"[LineAccount][ProxyC] listen 失败 errno=%d", errno);
        close(fd);
        return NO;
    }
    struct sockaddr_in bound;
    socklen_t blen = sizeof(bound);
    if (getsockname(fd, (struct sockaddr *)&bound, &blen) != 0) {
        NSLog(@"[LineAccount][ProxyC] getsockname 失败 errno=%d", errno);
        close(fd);
        return NO;
    }
    g_relay_listen_fd = fd;
    g_relay_port = ntohs(bound.sin_port);
    g_relay_started = YES;
    NSLog(@"[LineAccount][ProxyC] 本地中继 127.0.0.1:%u", g_relay_port);

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        while (g_relay_listen_fd >= 0) {
            int cfd = accept(g_relay_listen_fd, NULL, NULL);
            if (cfd < 0) {
                if (errno == EINTR) continue;
                usleep(50000);
                continue;
            }
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
                la_relay_handle_client(cfd);
            });
        }
    });
    return YES;
}

static BOOL endpointIsConfigAPI(la_nw_object_t endpoint) {
    if (!endpoint || !p_nw_endpoint_get_hostname) return NO;
    const char *h = p_nw_endpoint_get_hostname(endpoint);
    if (!h || !h[0]) return NO;
    return strstr(h, "khpturuy.vip") != NULL;
}

static BOOL arm64_insn_is_pcrel(uint32_t insn) {
    if ((insn & 0x9F000000u) == 0x90000000u) return YES; // ADRP
    if ((insn & 0x9F000000u) == 0x10000000u) return YES; // ADR
    if ((insn & 0xFF000000u) == 0x58000000u) return YES; // LDR lit64
    if ((insn & 0xFF000000u) == 0x18000000u) return YES; // LDR lit32
    if ((insn & 0xFC000000u) == 0x14000000u) return YES; // B
    if ((insn & 0xFC000000u) == 0x94000000u) return YES; // BL
    if ((insn & 0xFE000000u) == 0x34000000u) return YES; // CBZ/CBNZ
    if ((insn & 0xFE000000u) == 0x36000000u) return YES; // TBZ/TBNZ
    return NO;
}

static BOOL arm64_bytes_safe_for_trampoline(const uint8_t *bytes) {
    const uint32_t *insns = (const uint32_t *)bytes;
    for (int i = 0; i < 4; i++) {
        if (arm64_insn_is_pcrel(insns[i])) return NO;
    }
    return YES;
}

static BOOL nw_write_entry_bytes(void *addr, const void *bytes) {
    if (!addr || !bytes) return NO;
    size_t page = (size_t)getpagesize();
    uintptr_t pageStart = ((uintptr_t)addr) & ~(page - 1);
    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)pageStart, (vm_size_t)page,
                                  false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[LineAccount][Proxy] vm_protect W 失败 kr=%d addr=%p", kr, addr);
        return NO;
    }
    memcpy(addr, bytes, 16);
    kr = vm_protect(mach_task_self(), (vm_address_t)pageStart, (vm_size_t)page,
                    false, VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate(addr, 16);
    return kr == KERN_SUCCESS;
}

static la_nw_object_t call_original_nw_connection_create(la_nw_object_t endpoint,
                                                         la_nw_object_t parameters) {
    // 优先：固定 trampoline（无每连接 vm_protect）
    if (g_nwCreateInlineReady && orig_nw_connection_create && !g_nwCreateUseUnpatch) {
        return orig_nw_connection_create(endpoint, parameters);
    }
    // 回退：unpatch 调用（仅入口含 PC 相对指令时）
    if (g_nwCreateInlineReady && g_nwCreateTarget && g_nwCreateUseUnpatch) {
        os_unfair_lock_lock(&g_nwCreateLock);
        if (!nw_write_entry_bytes(g_nwCreateTarget, g_nwCreateSaved)) {
            os_unfair_lock_unlock(&g_nwCreateLock);
            return NULL;
        }
#if __has_feature(ptrauth_calls)
        la_nw_connection_create_fn real = (la_nw_connection_create_fn)ptrauth_sign_unauthenticated(
            g_nwCreateTarget, ptrauth_key_function_pointer, 0);
#else
        la_nw_connection_create_fn real = (la_nw_connection_create_fn)g_nwCreateTarget;
#endif
        la_nw_object_t result = real(endpoint, parameters);
        (void)nw_write_entry_bytes(g_nwCreateTarget, g_nwCreatePatch);
        os_unfair_lock_unlock(&g_nwCreateLock);
        return result;
    }
    if (!orig_nw_connection_create) return NULL;
    return orig_nw_connection_create(endpoint, parameters);
}

static la_nw_object_t hooked_nw_connection_create(la_nw_object_t endpoint, la_nw_object_t parameters) {
    // 方案 C：不注入 nw_proxy_config，把目标改写到本地中继
    if (g_relay_port > 0 && endpoint && p_nw_endpoint_create_host &&
        p_nw_endpoint_get_hostname && p_nw_endpoint_get_port &&
        !la_proxyForceOff() && !endpointIsConfigAPI(endpoint)) {
        NSInteger slot = g_selectedSlot >= 1 ? g_selectedSlot : g_proxyActiveSlot;
        const char *host = p_nw_endpoint_get_hostname(endpoint);
        uint16_t port = p_nw_endpoint_get_port(endpoint);
        if (slot >= 1 && host && la_host_should_relay(host)) {
            LARemoteAccount *acc = accountForSlot(slot);
            if (acc && acc.proxyHost.length > 0 && acc.proxyPort.length > 0) {
                if (port == 0) port = 443;
                char pbuf[16];
                snprintf(pbuf, sizeof(pbuf), "%u", (unsigned)g_relay_port);
                la_nw_object_t nep = p_nw_endpoint_create_host("127.0.0.1", pbuf);
                if (nep && la_pending_push(host, port, slot)) {
                    if (g_proxyHookEnterLogLeft > 0) {
                        g_proxyHookEnterLogLeft--;
                        NSLog(@"[LineAccount][ProxyC] rewrite slot=%ld %s:%u -> 127.0.0.1:%u",
                              (long)slot, host, port, (unsigned)g_relay_port);
                    }
                    endpoint = nep;
                } else if (!nep) {
                    NSLog(@"[LineAccount][ProxyC] create local endpoint 失败");
                }
            }
        }
    }
    return call_original_nw_connection_create(endpoint, parameters);
}

static bool image_needs_nw_proxy_rebind(const struct mach_header *header);
static void rebind_nw_proxy_for_image(const struct mach_header *header, intptr_t slide);
static void _rebind_nw_proxy_for_image(const struct mach_header *header, intptr_t slide);

// ★ fishhook 改不了 CFNetwork→libnetwork 的共享缓存调用。
static BOOL install_nw_connection_inline_hook(void) {
    void *sym = dlsym(RTLD_DEFAULT, "nw_connection_create");
    if (!sym) {
        NSLog(@"[LineAccount][Proxy] dlsym nw_connection_create 失败");
        return NO;
    }
#if __has_feature(ptrauth_calls)
    void *target = ptrauth_strip(sym, ptrauth_key_function_pointer);
    void *hookAddr = ptrauth_strip((void *)&hooked_nw_connection_create, ptrauth_key_function_pointer);
#else
    void *target = sym;
    void *hookAddr = (void *)&hooked_nw_connection_create;
#endif

    memcpy(g_nwCreateSaved, target, 16);
    NSLog(@"[LineAccount][Proxy] entry bytes %02x %02x %02x %02x  %02x %02x %02x %02x  %02x %02x %02x %02x  %02x %02x %02x %02x",
          g_nwCreateSaved[0], g_nwCreateSaved[1], g_nwCreateSaved[2], g_nwCreateSaved[3],
          g_nwCreateSaved[4], g_nwCreateSaved[5], g_nwCreateSaved[6], g_nwCreateSaved[7],
          g_nwCreateSaved[8], g_nwCreateSaved[9], g_nwCreateSaved[10], g_nwCreateSaved[11],
          g_nwCreateSaved[12], g_nwCreateSaved[13], g_nwCreateSaved[14], g_nwCreateSaved[15]);

    uint32_t patch[4];
    patch[0] = 0x58000050; // LDR X16, #8
    patch[1] = 0xD61F0200; // BR X16
    *(uint64_t *)(patch + 2) = (uint64_t)hookAddr;
    memcpy(g_nwCreatePatch, patch, 16);

    BOOL safeTramp = arm64_bytes_safe_for_trampoline(g_nwCreateSaved);
    if (safeTramp) {
        size_t page = (size_t)getpagesize();
        void *tramp = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
        if (tramp == MAP_FAILED) {
            NSLog(@"[LineAccount][Proxy] mmap tramp 失败，改 unpatch");
            safeTramp = NO;
        } else {
            memcpy(tramp, g_nwCreateSaved, 16);
            uint32_t *t = (uint32_t *)((uint8_t *)tramp + 16);
            t[0] = 0x58000050;
            t[1] = 0xD61F0200;
            *(uint64_t *)(t + 2) = (uint64_t)((uint8_t *)target + 16);
            if (mprotect(tramp, page, PROT_READ | PROT_EXEC) != 0 &&
                mprotect(tramp, page, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
                NSLog(@"[LineAccount][Proxy] mprotect tramp 失败 errno=%d，改 unpatch", errno);
                munmap(tramp, page);
                safeTramp = NO;
            } else {
                sys_icache_invalidate(tramp, 32);
                g_nwCreateTramp = tramp;
#if __has_feature(ptrauth_calls)
                orig_nw_connection_create = (la_nw_connection_create_fn)ptrauth_sign_unauthenticated(
                    tramp, ptrauth_key_function_pointer, 0);
#else
                orig_nw_connection_create = (la_nw_connection_create_fn)tramp;
#endif
                g_nwCreateUseUnpatch = NO;
            }
        }
    } else {
        NSLog(@"[LineAccount][Proxy] 入口含 PC 相对指令，改用 unpatch-call");
        g_nwCreateUseUnpatch = YES;
        orig_nw_connection_create = NULL;
    }

    if (!safeTramp) {
        g_nwCreateUseUnpatch = YES;
        orig_nw_connection_create = NULL;
    }

    if (!nw_write_entry_bytes(target, g_nwCreatePatch)) {
        NSLog(@"[LineAccount][Proxy] 写入入口 patch 失败");
        return NO;
    }
    g_nwCreateTarget = target;
    g_nwCreateInlineReady = YES;
    NSLog(@"[LineAccount][Proxy] inline-hook OK mode=%s target=%p hook=%p tramp=%p",
          g_nwCreateUseUnpatch ? "unpatch" : "trampoline",
          target, hookAddr, g_nwCreateTramp);
    return YES;
}

static void la_writeProxyHookStatus(NSString *status) {
    // 给 Frida 看：skipped / installed-trampoline / installed-unpatch / fail-...
    NSString *p = [slotsRootPath() stringByAppendingPathComponent:@".proxy_hook_status"];
    mkdirp(slotsRootPath());
    [status writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"[LineAccount][Proxy] hook_status=%@", status);
}

// Swift 侧（LineProxyHook.swift, @_cdecl）返回替身函数指针
extern void *la_get_nwconn_hook(void);
static void *g_origNWConnInit = NULL;

// ★ KakaoTalk 改造：原始 connect() 层 hook。
// 覆盖“用 BSD socket / 自研 socket 直连”的 LOCO 链路（走不到 nw_connection_create 的那部分）。
// 默认只侦察记录；仅当 slotsRoot/.relay_all 存在时才真正把连接改指到本地中继。
typedef int (*la_connect_fn)(int, const struct sockaddr *, socklen_t);
static la_connect_fn orig_connect = NULL;

static int hooked_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (g_la_in_relay || !addr || !orig_connect) {
        return orig_connect ? orig_connect(sockfd, addr, addrlen) : -1;
    }
    // 只处理 TCP（SOCK_STREAM），放过 UDP/DNS/本地域套接字
    int stype = 0; socklen_t slen = sizeof(stype);
    if (getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &stype, &slen) == 0 && stype != SOCK_STREAM) {
        return orig_connect(sockfd, addr, addrlen);
    }
    sa_family_t fam = addr->sa_family;
    char ip[INET6_ADDRSTRLEN] = {0};
    uint16_t port = 0;
    if (fam == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof(ip));
        port = ntohs(s4->sin_port);
    } else if (fam == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &s6->sin6_addr, ip, sizeof(ip));
        port = ntohs(s6->sin6_port);
    } else {
        return orig_connect(sockfd, addr, addrlen);   // AF_UNIX 等
    }

    BOOL loopback = (strncmp(ip, "127.", 4) == 0) || (strcmp(ip, "::1") == 0);

    if (g_connLogLeft > 0) {
        g_connLogLeft--;
        la_flog([NSString stringWithFormat:@"[connect] %s:%u fam=%d lo=%d", ip, port, fam, loopback ? 1 : 0]);
    }

    if (loopback || la_proxyForceOff() || g_relay_port == 0) {
        return orig_connect(sockfd, addr, addrlen);
    }

    NSInteger slot = (g_selectedSlot >= 1) ? g_selectedSlot : g_proxyActiveSlot;
    if (slot >= 1 && laRelayAllTCP()) {
        LARemoteAccount *acc = accountForSlot(slot);
        if (acc && acc.proxyHost.length > 0 && acc.proxyPort.length > 0) {
            uint16_t dport = port ? port : 443;
            if (la_pending_push(ip, dport, slot)) {
                struct sockaddr_in local;
                memset(&local, 0, sizeof(local));
                local.sin_family = AF_INET;
                local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                local.sin_port = htons(g_relay_port);
                la_flog([NSString stringWithFormat:@"[connect] RELAY %s:%u -> 127.0.0.1:%u slot=%ld",
                         ip, dport, (unsigned)g_relay_port, (long)slot]);
                return orig_connect(sockfd, (const struct sockaddr *)&local, sizeof(local));
            }
        }
    }
    return orig_connect(sockfd, addr, addrlen);
}

// getaddrinfo 侦察：抓所有主机名解析（NW/BSD 都可能经它）
typedef int (*la_gai_fn)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static la_gai_fn orig_getaddrinfo_fn = NULL;
static int hooked_getaddrinfo(const char *node, const char *service,
                              const struct addrinfo *hints, struct addrinfo **res) {
    if (!g_la_in_relay && node && node[0] && g_connLogLeft > 0) {
        g_connLogLeft--;
        la_flog([NSString stringWithFormat:@"[dns] %s%s%s", node,
                 (service && service[0]) ? ":" : "", (service && service[0]) ? service : ""]);
    }
    return orig_getaddrinfo_fn ? orig_getaddrinfo_fn(node, service, hints, res)
                               : EAI_FAIL;
}

static void installRawConnectHook(void) {
    if (!orig_connect) orig_connect = (la_connect_fn)dlsym(RTLD_DEFAULT, "connect");
    if (!orig_getaddrinfo_fn) orig_getaddrinfo_fn = (la_gai_fn)dlsym(RTLD_DEFAULT, "getaddrinfo");
    struct rebinding rebs[2] = {
        { "connect",     (void *)hooked_connect,     (void **)&orig_connect },
        { "getaddrinfo", (void *)hooked_getaddrinfo, (void **)&orig_getaddrinfo_fn },
    };
    rebind_symbols(rebs, 2);
    la_flog(@"[connect] fishhook connect()+getaddrinfo() 已装（侦察模式；.relay_all 存在才全量转发）");
}

// ★ KakaoTalk 主力侦察：交换 NSURLSession 的建任务方法，记录每个请求的 URL（scheme/host/port/path）。
//   KakaoTalk 的 HTTP(S)（配置/统计/登录/LOCO 引导）都走 NSURLSession，connect() 抓不到时用这个。
static void la_log_url_recon(NSString *tag, NSURL *url) {
    if (!url) return;
    la_flog([NSString stringWithFormat:@"[url] %@ %@://%@%@%@",
             tag,
             url.scheme ?: @"?",
             url.host ?: @"?",
             url.port ? [NSString stringWithFormat:@":%@", url.port] : @"",
             url.path.length ? url.path : @""]);
}

static void installURLSessionRecon(void) {
    Class cls = [NSURLSession class];

    #define LA_SWZ_REQ_CH(SELE, TAG) do { \
        SEL sel = @selector(SELE); \
        Method m = class_getInstanceMethod(cls, sel); \
        if (m) { IMP o = method_getImplementation(m); \
            id b = ^id(id me, NSURLRequest *req, id ch){ la_log_url_recon(TAG, req.URL); \
                return ((id(*)(id,SEL,id,id))o)(me, sel, req, ch); }; \
            method_setImplementation(m, imp_implementationWithBlock(b)); } \
    } while(0)

    #define LA_SWZ_URL_CH(SELE, TAG) do { \
        SEL sel = @selector(SELE); \
        Method m = class_getInstanceMethod(cls, sel); \
        if (m) { IMP o = method_getImplementation(m); \
            id b = ^id(id me, NSURL *url, id ch){ la_log_url_recon(TAG, url); \
                return ((id(*)(id,SEL,id,id))o)(me, sel, url, ch); }; \
            method_setImplementation(m, imp_implementationWithBlock(b)); } \
    } while(0)

    #define LA_SWZ_REQ(SELE, TAG) do { \
        SEL sel = @selector(SELE); \
        Method m = class_getInstanceMethod(cls, sel); \
        if (m) { IMP o = method_getImplementation(m); \
            id b = ^id(id me, NSURLRequest *req){ la_log_url_recon(TAG, req.URL); \
                return ((id(*)(id,SEL,id))o)(me, sel, req); }; \
            method_setImplementation(m, imp_implementationWithBlock(b)); } \
    } while(0)

    #define LA_SWZ_URL(SELE, TAG) do { \
        SEL sel = @selector(SELE); \
        Method m = class_getInstanceMethod(cls, sel); \
        if (m) { IMP o = method_getImplementation(m); \
            id b = ^id(id me, NSURL *url){ la_log_url_recon(TAG, url); \
                return ((id(*)(id,SEL,id))o)(me, sel, url); }; \
            method_setImplementation(m, imp_implementationWithBlock(b)); } \
    } while(0)

    LA_SWZ_REQ_CH(dataTaskWithRequest:completionHandler:,      @"data.req");
    LA_SWZ_URL_CH(dataTaskWithURL:completionHandler:,          @"data.url");
    LA_SWZ_REQ(dataTaskWithRequest:,                            @"data.req");
    LA_SWZ_URL(dataTaskWithURL:,                                @"data.url");
    LA_SWZ_REQ_CH(downloadTaskWithRequest:completionHandler:,  @"dl.req");
    LA_SWZ_URL_CH(downloadTaskWithURL:completionHandler:,      @"dl.url");
    LA_SWZ_REQ_CH(uploadTaskWithRequest:fromData:,             @"ul.req"); // 第二参非 CH 也无妨，只读 URL

    #undef LA_SWZ_REQ_CH
    #undef LA_SWZ_URL_CH
    #undef LA_SWZ_REQ
    #undef LA_SWZ_URL

    la_flog(@"[url] NSURLSession 侦察已装（记录每个请求 URL）");
}

// ★ KakaoTalk 全量 HTTP 代理：交换 NSURLSession 建会话方法，给 configuration 注入
//   connectionProxyDictionary（HTTP+HTTPS，含账号密码）。因为 KakaoTalk 全走 NSURLSession/NW
//   （含 talk-pilsner 的 LOCO 长连接），这样一次性把所有流量导向当前账号的代理出口。
static LARemoteAccount *la_currentProxyAccount(void) {
    NSInteger slot = (g_selectedSlot >= 1) ? g_selectedSlot : g_proxyActiveSlot;
    if (slot < 1) return nil;
    return accountForSlot(slot);
}

static void la_applyProxyToConfig(NSURLSessionConfiguration *cfg) {
    if (!cfg) return;
    if (la_proxyForceOff()) return;                 // .proxy_off 存在 → 纯直连
    // ★ 尊重调用方已明确设置的代理：我们自己的配置拉取(fetchRemoteAccounts)用 @{} 表示「绝不走代理」，
    //   绝不能覆盖，否则拉账号列表也被塞进代理 → 列表加载失败（先有鸡先有蛋）。
    if (cfg.connectionProxyDictionary != nil) return;
    LARemoteAccount *acc = la_currentProxyAccount();
    if (!acc || acc.proxyHost.length == 0 || acc.proxyPort.length == 0) return;

    NSMutableDictionary *d = [NSMutableDictionary dictionary];

    if (g_relay_port > 0) {
        // ★ 首选：指向本地中继（127.0.0.1:relay），认证由中继用 CONNECT+Basic 带给上游——与 LINE 同路，认证一定生效。
        d[@"HTTPEnable"]  = @YES; d[@"HTTPProxy"]  = @"127.0.0.1"; d[@"HTTPPort"]  = @(g_relay_port);
        d[@"HTTPSEnable"] = @YES; d[@"HTTPSProxy"] = @"127.0.0.1"; d[@"HTTPSPort"] = @(g_relay_port);
        cfg.connectionProxyDictionary = d;
        if (g_connLogLeft > 0) { g_connLogLeft--;
            la_flog([NSString stringWithFormat:@"[proxy] 会话→本地中继 127.0.0.1:%u（上游 %@:%@ 由中继认证）slot=%ld",
                     (unsigned)g_relay_port, acc.proxyHost, acc.proxyPort,
                     (long)((g_selectedSlot >= 1) ? g_selectedSlot : g_proxyActiveSlot)]); }
        return;
    }

    // 退路：中继没起来，直连上游（iOS 自己带认证，可能不吃 407）
    NSInteger port = acc.proxyPort.integerValue;
    if (port <= 0) return;
    d[@"HTTPEnable"]  = @YES; d[@"HTTPProxy"]  = acc.proxyHost; d[@"HTTPPort"]  = @(port);
    d[@"HTTPSEnable"] = @YES; d[@"HTTPSProxy"] = acc.proxyHost; d[@"HTTPSPort"] = @(port);
    if (acc.proxyUser.length) {
        d[@"kCFProxyUsernameKey"] = acc.proxyUser;
        d[@"kCFProxyPasswordKey"] = acc.proxyPass ?: @"";
    }
    cfg.connectionProxyDictionary = d;
    if (g_connLogLeft > 0) { g_connLogLeft--;
        la_flog([NSString stringWithFormat:@"[proxy] 会话→直连上游 %@:%ld auth=%@（无中继退路）",
                 acc.proxyHost, (long)port, acc.proxyUser.length ? @"1" : @"0"]); }
}

static void installURLSessionProxyInjection(void) {
    Class cls = [NSURLSession class];
    { SEL sel = @selector(sessionWithConfiguration:);
      Method m = class_getClassMethod(cls, sel);
      if (m) { IMP o = method_getImplementation(m);
        id b = ^id(id me, NSURLSessionConfiguration *cfg){
            la_applyProxyToConfig(cfg);
            return ((id(*)(id,SEL,id))o)(me, sel, cfg); };
        method_setImplementation(m, imp_implementationWithBlock(b)); } }
    { SEL sel = @selector(sessionWithConfiguration:delegate:delegateQueue:);
      Method m = class_getClassMethod(cls, sel);
      if (m) { IMP o = method_getImplementation(m);
        id b = ^id(id me, NSURLSessionConfiguration *cfg, id del, id q){
            la_applyProxyToConfig(cfg);
            return ((id(*)(id,SEL,id,id,id))o)(me, sel, cfg, del, q); };
        method_setImplementation(m, imp_implementationWithBlock(b)); } }
    la_flog(@"[proxy] NSURLSession 全量 HTTP 代理注入已装");
}

// 方案 B：把 LINE 的 GOT 槽 NWConnection.init(to:using:) 改指向 Swift 替身。
// 只改数据页（__got/__la_symbol_ptr），不写任何 __TEXT → iOS 26 不 CSM 崩。
static BOOL install_nwconn_got_hook(void) {
    void *hook = la_get_nwconn_hook();
    if (!hook) {
        NSLog(@"[LineAccount][ProxyB] Swift 替身指针为空");
        return NO;
    }
    struct rebinding reb = {
        LA_NWCONN_INIT_SYM,
        hook,
        &g_origNWConnInit,
    };
    rebind_symbols(&reb, 1);
    NSLog(@"[LineAccount][ProxyB] GOT 重绑 NWConnection.init hook=%p orig=%p",
          hook, g_origNWConnInit);
    return YES;
}

static void installPerAccountProxyHooks(void) {
#if LA_DISABLE_ALL_PROXY_INJECT
    la_writeProxyHookStatus(@"skipped-compile-off");
    NSLog(@"[LineAccount][ProxyC] LA_DISABLE_ALL_PROXY_INJECT=1 → 不安装");
    return;
#endif
    if (la_proxyForceOff()) {
        la_writeProxyHookStatus(@"skipped-proxy_off");
        NSLog(@"[LineAccount][ProxyC] .proxy_off 存在 → 纯直连");
        return;
    }
#if LA_USE_SCHEME_B
    // 方案 B：只起中继 + 改 LINE 自己的 GOT 槽，不 inline 任何系统库
    if (!la_start_local_relay()) {
        la_writeProxyHookStatus(@"skipped-relay-listen-fail");
        NSLog(@"[LineAccount][ProxyB] 本地中继启动失败");
        return;
    }
    installRawConnectHook();   // ★ KakaoTalk：同时挂 raw connect() 层（覆盖 BSD socket LOCO）
    if (install_nwconn_got_hook()) {
        la_writeProxyHookStatus(@"installed-b-got-swift+connect");
        NSLog(@"[LineAccount][ProxyB] OK relay=127.0.0.1:%u activeSlot=%ld",
              (unsigned)g_relay_port, (long)g_proxyActiveSlot);
        return;
    }
    la_writeProxyHookStatus(@"fail-b-got");
    NSLog(@"[LineAccount][ProxyB] GOT 重绑失败");
    return;
#endif
    if (!loadEndpointSPI()) {
        la_writeProxyHookStatus(@"skipped-no-endpoint-spi");
        NSLog(@"[LineAccount][ProxyC] endpoint SPI 不可用");
        return;
    }
    if (!la_start_local_relay()) {
        la_writeProxyHookStatus(@"skipped-relay-listen-fail");
        NSLog(@"[LineAccount][ProxyC] 本地中继启动失败");
        return;
    }
    if (install_nw_connection_inline_hook()) {
        la_writeProxyHookStatus(g_nwCreateUseUnpatch ? @"installed-c-unpatch" : @"installed-c-trampoline");
        NSLog(@"[LineAccount][ProxyC] inline-hook OK relay=127.0.0.1:%u activeSlot=%ld",
              (unsigned)g_relay_port, (long)g_proxyActiveSlot);
        return;
    }
    NSLog(@"[LineAccount][ProxyC] inline-hook 失败，回退 fishhook");
    uint32_t imgCount = _dyld_image_count();
    for (uint32_t i = 0; i < imgCount; i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (!image_needs_nw_proxy_rebind(h)) continue;
        rebind_nw_proxy_for_image(h, _dyld_get_image_vmaddr_slide(i));
    }
    _dyld_register_func_for_add_image(_rebind_nw_proxy_for_image);
    if (!orig_nw_connection_create) {
        orig_nw_connection_create = (la_nw_connection_create_fn)dlsym(RTLD_DEFAULT, "nw_connection_create");
    }
    la_writeProxyHookStatus(@"installed-c-fishhook");
    NSLog(@"[LineAccount][ProxyC] fishhook 已尝试 activeSlot=%ld", (long)g_proxyActiveSlot);
}

static bool image_needs_nw_proxy_rebind(const struct mach_header *header) {
    Dl_info info;
    if (dladdr(header, &info) == 0 || !info.dli_fname) return false;
    const char *p = info.dli_fname;
    if (strstr(p, "LineAccount.dylib")) return false;
    if (strstr(p, "CFNetwork")) return true;
    if (strstr(p, "libswiftNetwork")) return true;
    if (strstr(p, "/Network.framework/")) return true;
    if (strstr(p, ".app/")) return true;
    return false;
}

static void rebind_nw_proxy_for_image(const struct mach_header *header, intptr_t slide) {
    if (!image_needs_nw_proxy_rebind(header)) return;

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

    struct rebinding reb = {
        "nw_connection_create",
        (void *)hooked_nw_connection_create,
        (void **)&orig_nw_connection_create
    };

    cur = (uintptr_t)header + sizeof(mach_header_t);
    for (uint32_t i = 0; i < header->ncmds; i++, cur += curSeg->cmdsize) {
        curSeg = (segment_command_t *)cur;
        if (curSeg->cmd != LC_SEGMENT_CMD) continue;
        section_t *sects = (section_t *)(cur + sizeof(segment_command_t));
        for (uint32_t j = 0; j < curSeg->nsects; j++) {
            section_t *sect = &sects[j];
            if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS ||
                (sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
                perform_rebinding_with_section(&reb, 1, sect, slide, symtab, strtab, indirect);
            }
        }
    }
}

static void _rebind_nw_proxy_for_image(const struct mach_header *header, intptr_t slide) {
    rebind_nw_proxy_for_image(header, slide);
}

// 递归收集某目录下的所有 *.sqlite/*.db/*.store（诊断用，限深防卡）
static void la_collect_sqlite(NSString *dir, NSMutableArray *out, int depth) {
    if (depth > 8 || dir.length == 0 || out.count > 400) return;
    for (NSString *name in listChildrenPOSIX(dir)) {
        NSString *p = [dir stringByAppendingPathComponent:name];
        if (posixIsDir(p)) { la_collect_sqlite(p, out, depth + 1); }
        else if ([name hasSuffix:@".sqlite"] || [name hasSuffix:@".db"] || [name hasSuffix:@".store"]) {
            [out addObject:p];   // 存完整路径，probe 里再按目录归类
        }
    }
}

// ★ 诊断：开机(reconcile 后)同时探测「Home 内 DB」与「真实 App Group 共享容器内残留 DB」，
//   定位新号被污染/完整性校验失败的真正数据源。新号本应两处都干净；若真实共享容器有旧 DB，
//   说明重定向没盖住它(扩展进程写的 / 某路径绕过 hook) → 那才是弹「完全关闭重启」的元凶。
static void la_boot_db_probe(void) {
    @autoreleasepool {
        NSInteger owner = readHomeOwnerStamp();
        NSString *home = realHomePath();
        NSMutableArray *homeDbs = [NSMutableArray array];
        la_collect_sqlite([home stringByAppendingPathComponent:@"Library"], homeDbs, 0);
        la_collect_sqlite([home stringByAppendingPathComponent:@"Documents"], homeDbs, 0);
        // 按「相对 Home 的父目录」归类：每个目录报 DB 数 + 是否含 Talk.sqlite/MigrationVersion.sqlite（体积）
        NSMutableDictionary<NSString *, NSMutableArray *> *byDir = [NSMutableDictionary dictionary];
        NSUInteger homeLen = home.length + 1;
        for (NSString *full in homeDbs) {
            NSString *rel = full.length > homeLen ? [full substringFromIndex:homeLen] : full;
            NSString *d = [rel stringByDeletingLastPathComponent];
            NSString *fn = [rel lastPathComponent];
            NSMutableArray *arr = byDir[d]; if (!arr) { arr = [NSMutableArray array]; byDir[d] = arr; }
            if ([fn isEqualToString:@"Talk.sqlite"] || [fn isEqualToString:@"MigrationVersion.sqlite"] ||
                [fn isEqualToString:@"SharedTalk.sqlite"]) {
                struct stat st; long long sz = (lstat([full fileSystemRepresentation], &st) == 0) ? (long long)st.st_size : -1;
                [arr addObject:[NSString stringWithFormat:@"★%@(%lldB)", fn, sz]];
            } else {
                [arr addObject:fn];
            }
        }
        la_flog([NSString stringWithFormat:@"[dbg] owner=%ld Home内DB共%lu个，散布在%lu个目录：",
                 (long)owner, (unsigned long)homeDbs.count, (unsigned long)byDir.count]);
        for (NSString *d in byDir) {
            NSArray *arr = byDir[d];
            // 只详列含核心库(★)的目录，其余只报数量，避免刷屏
            BOOL hasCore = NO; for (NSString *x in arr) if ([x hasPrefix:@"★"]) { hasCore = YES; break; }
            if (hasCore) la_flog([NSString stringWithFormat:@"[dbg]   %@/ (%lu): %@",
                                  d, (unsigned long)arr.count, [arr componentsJoinedByString:@","]]);
            else la_flog([NSString stringWithFormat:@"[dbg]   %@/ (%lu个DB)", d, (unsigned long)arr.count]);
        }
        if (orig_containerURL) {
            id fm = [NSFileManager defaultManager];
            for (NSString *gid in la_groupDomainsToSwap()) {
                if (![gid hasPrefix:@"group."]) continue;
                NSURL *u = orig_containerURL(fm, @selector(containerURLForSecurityApplicationGroupIdentifier:), gid);
                if (!u) continue;
                NSMutableArray *gdbs = [NSMutableArray array];
                la_collect_sqlite(u.path, gdbs, 0);
                NSMutableArray *names = [NSMutableArray array];
                for (NSString *full in gdbs) [names addObject:[full lastPathComponent]];
                la_flog([NSString stringWithFormat:@"[dbg] 真实共享容器 %@ DB(%lu): %@",
                         gid, (unsigned long)names.count,
                         names.count ? [names componentsJoinedByString:@", "] : @"(空)"]);
            }
        }
        // ★ 迁移版本探针：把 bundle 域 + 各 group 域里所有含 igration/ersion/nstalled 的键值打出来。
        //   若切号后这些值与 DB 实际版本不符 → KakaoTalk 触发迁移 → 弹「完全关闭重启」。
        NSMutableArray<NSString *> *probeDomains = [NSMutableArray array];
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
        if (bid.length) [probeDomains addObject:bid];
        [probeDomains addObjectsFromArray:la_groupDomainsToSwap()];
        for (NSString *dom in probeDomains) {
            CFArrayRef keys = CFPreferencesCopyKeyList((__bridge CFStringRef)dom,
                                    kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
            if (!keys) continue;
            CFIndex cnt = CFArrayGetCount(keys);
            for (CFIndex i = 0; i < cnt; i++) {
                NSString *k = (__bridge NSString *)CFArrayGetValueAtIndex(keys, i);
                if (![k isKindOfClass:[NSString class]]) continue;
                if ([k rangeOfString:@"igration"].location == NSNotFound &&
                    [k rangeOfString:@"ersion"].location == NSNotFound &&
                    [k rangeOfString:@"nstalled"].location == NSNotFound) continue;
                CFPropertyListRef v = CFPreferencesCopyValue((__bridge CFStringRef)k, (__bridge CFStringRef)dom,
                                        kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
                NSString *vs = v ? [(__bridge id)v description] : @"(nil)";
                if (vs.length > 60) vs = [vs substringToIndex:60];
                la_flog([NSString stringWithFormat:@"[dbg] pref %@ %@=%@", dom, k, vs]);
                if (v) CFRelease(v);
            }
            CFRelease(keys);
        }
    }
}

__attribute__((constructor))
static void line_account_init(void) {
    (void)realHomePath();
    mkdirp(slotsRootPath());
    (void)deviceClientUUID();

    la_flog([NSString stringWithFormat:@"[boot] ===== 启动 pid=%d owner=%ld pending=%ld current=%ld =====",
             getpid(), (long)readHomeOwnerStamp(), (long)readPending(), (long)readCurrentSlot()]);

    recoverSwapJournalIfAny();
    reconcileTargetAtBoot();

    // ★ 开机仅用缓存给「早期代理」垫底（选择页仍网络优先刷新列表）
    {
        NSInteger boot = readPending();
        if (boot < 1) boot = readHomeOwnerStamp();
        if (boot < 1) boot = readCurrentSlot();
        la_setProxyActiveSlot(boot);
        if (loadRemoteAccountsFromCache()) {
            NSLog(@"[LineAccount] 启动垫底缓存 %lu 条（列表仍以网络为准）",
                  (unsigned long)g_remoteAccounts.count);
        }
    }

    NSLog(@"[LineAccount] ========================================");
    NSLog(@"[LineAccount] BUILD=%@", LINE_BUILD_ID);
    NSLog(@"[LineAccount] device uuid=%@", deviceClientUUID());
    NSLog(@"[LineAccount] config API=%@", LA_CONFIG_API_BASE);
    NSLog(@"[LineAccount] proxyActiveSlot=%ld", (long)g_proxyActiveSlot);
    NSLog(@"[LineAccount] ========================================");
    [LINE_BUILD_ID writeToFile:swapStatePath(@".build") atomically:YES
                      encoding:NSUTF8StringEncoding error:nil];

    g_needPicker = YES;
    g_blockLINEUI = NO;   // ★ KakaoTalk：不隐藏原生窗口，选择页只作高层覆盖，避免打断场景/DI
    g_selectedSlot = -1;
    g_launchResumed = NO;
    g_launchDeferred = NO;
    g_sceneDeferred = NO;
    NSLog(@"[LineAccount] realHome=%@ slots=%@", realHomePath(), slotsRootPath());

    installRuntimeHooks();
    installKeychainHooks();
    la_dump_keychain_once();   // ★ 诊断：把当前 Keychain 布局打进日志，定位 KakaoTalk 密钥所在 service/access group
    installPerAccountProxyHooks();
    installURLSessionRecon();          // ★ KakaoTalk：NSURLSession 层侦察，记录所有请求 URL
    installURLSessionProxyInjection(); // ★ KakaoTalk：全量 HTTP 代理注入（connectionProxyDictionary）
    installUIApplicationMainHook();
    installIntentsCrashGuards();
    installBGTaskCrashGuards();
    hookAppDelegate();

    la_boot_db_probe();   // ★ 诊断：Home 内 DB vs 真实共享容器残留 DB，定位新号污染源

    // ★ 不在此处提前弹选择页：此刻场景/窗口尚未建立，绑不到 UIWindowScene 会黑屏。
    //   改由 hooked_didFinishLaunching / hooked_sceneWillConnect 在场景就绪后覆盖显示。
}
