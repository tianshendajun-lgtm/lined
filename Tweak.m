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

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Wunused-function"

#define ACCOUNT_COUNT 4
#define SLOT_DIR_NAME @"LineAccountSlots"
#define SELECTED_SLOT_KEY @"LineAccount.SelectedSlot"
#define PENDING_ENTER_KEY @"LineAccount.PendingEnter" // 选完杀进程后，下次启动直接进该槽

static NSInteger g_selectedSlot = -1;   // 0=临时, 1..4=账号
static BOOL g_pickerShown = NO;
static BOOL g_hooksInstalled = NO;
static BOOL g_needPicker = NO;      // 本次启动要先选账号
static BOOL g_blockLINEUI = NO;     // 挡住 LINE 原窗口，避免先闪登录页
static UIWindow *pickerWindow = nil;
static IMP orig_makeKeyAndVisible = NULL;

#pragma mark - 路径工具

static NSString *slotsRootPath(void) {
    NSString *home = NSHomeDirectory();
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
    // 已存在
    struct stat st;
    if (stat(cpath, &st) == 0) return;

    NSString *parent = [path stringByDeletingLastPathComponent];
    if (parent.length > 0 && ![parent isEqualToString:path] && ![parent isEqualToString:@"/"]) {
        mkdirp(parent);
    }
    mkdir(cpath, 0755);
}

static void ensureSlotDirectories(NSInteger slot) {
    // slot==0：选择页出现前的临时沙盒，防止 App Group URL 为 nil
    NSArray *subs = @[
        @"Documents",
        @"Library/Preferences",
        @"Library/Caches",
        @"Library/Application Support",
        @"Library/Application Support/Messages",
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
}

#pragma mark - 元数据（写在 LineAccountSlots 下，不被 remap）

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
    if ([path containsString:SLOT_DIR_NAME]) return NO;
    // g_selectedSlot>=0 时启用（含临时槽 0）
    if (g_selectedSlot < 0) return NO;
    NSString *home = NSHomeDirectory();
    if ([path hasPrefix:home]) return YES;
    if ([path containsString:@"/Library/Group Containers/"] ||
        [path containsString:@"group.com.linecorp"]) {
        return YES;
    }
    return NO;
}

static NSString *remapPath(NSString *path) {
    if (g_selectedSlot < 0 || !pathNeedsRemap(path)) return path;

    NSString *home = NSHomeDirectory();
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
typedef NSString * (*NSHomeDirectory_t)(void);

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
    // 重签包通常没有 App Group 权限，系统会返回 nil → LINE 直接崩
    // 所以只要有 groupId，就始终返回我们合成的容器路径
    if (groupId.length > 0) {
        NSInteger slot = g_selectedSlot >= 0 ? g_selectedSlot : 0;
        ensureSlotDirectories(slot);
        NSString *path = [[slotHomePath(slot)
                           stringByAppendingPathComponent:@"AppGroup"]
                          stringByAppendingPathComponent:groupId];
        mkdirp(path);
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

static BOOL hooked_createDirectoryURL(id self, SEL _cmd, NSURL *url, BOOL intermediates,
                                      NSDictionary *attr, NSError **err) {
    if (isBogusObjPtr((__bridge void *)url)) {
        url = urlFromMaybeBogus(url);
        if (isBogusObjPtr((__bridge void *)url)) {
            NSLog(@"[LineAccount] blocked createDirectoryAtURL:bogus/nil");
            if (err) {
                *err = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileWriteInvalidFileNameError
                                       userInfo:@{NSLocalizedDescriptionKey: @"URL is bogus (blocked)"}];
            }
            return NO;
        }
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
    return ((BOOL(*)(id,SEL,NSString*,BOOL,NSDictionary*,NSError**))orig_createDirectory)
        (self, _cmd, remapPath(path), intermediates, attr, err);
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
    return ((BOOL(*)(id,SEL,NSString*,NSData*,NSDictionary*))orig_createFile)
        (self, _cmd, remapPath(path), data, attr);
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

static NSURL *syntheticStoreURLTokens(NSString *a, NSString *b) {
    NSInteger slot = activeSlotOrZero();
    ensureSlotDirectories(slot);
    if (a.length == 0) a = @"store";
    NSString *path = [[slotHomePath(slot)
                       stringByAppendingPathComponent:@"Library/Application Support/LineStores"]
                      stringByAppendingPathComponent:a];
    if (b.length) path = [path stringByAppendingPathComponent:b];
    mkdirp(path);
    return [NSURL fileURLWithPath:path isDirectory:YES];
}

// + privateFileStoresAreAccessible
static BOOL (*orig_privateFileStoresAreAccessible)(Class, SEL) = NULL;
static BOOL hooked_privateFileStoresAreAccessible(Class cls, SEL sel) {
    (void)cls; (void)sel;
    return YES;
}

// 重签包无 App Group：原 fileURL* 内部常对坏状态发消息 → AV。
// 策略：完全不调 orig，只返回槽内合成路径。

// + fileURLForStoreType:  （NSInteger 枚举）
static NSURL *(*orig_fileURLForStoreType)(Class, SEL, NSInteger) = NULL;
static NSURL *hooked_fileURLForStoreType(Class cls, SEL sel, NSInteger storeType) {
    (void)cls; (void)sel;
    return syntheticStoreURLTokens([NSString stringWithFormat:@"st%ld", (long)storeType], nil);
}

// + fileURLForStore:  （store 也可能是整数枚举）
static NSURL *(*orig_fileURLForStore)(Class, SEL, id) = NULL;
static NSURL *hooked_fileURLForStore(Class cls, SEL sel, id store) {
    (void)cls; (void)sel;
    return syntheticStoreURLTokens(tokenFromId(store), nil);
}

// + fileURLForStore:ofType:  （type 几乎肯定是 NSInteger）
static NSURL *(*orig_fileURLForStoreOfType)(Class, SEL, id, NSInteger) = NULL;
static NSURL *hooked_fileURLForStoreOfType(Class cls, SEL sel, id store, NSInteger type) {
    (void)cls; (void)sel;
    return syntheticStoreURLTokens(tokenFromId(store),
                                   [NSString stringWithFormat:@"ty%ld", (long)type]);
}

// + fileURLForStore:substore:
static NSURL *(*orig_fileURLForStoreSubstore)(Class, SEL, id, id) = NULL;
static NSURL *hooked_fileURLForStoreSubstore(Class cls, SEL sel, id store, id sub) {
    (void)cls; (void)sel;
    return syntheticStoreURLTokens(tokenFromId(store), tokenFromId(sub));
}

// + fileURLForFileNamed:inStore:
static NSURL *(*orig_fileURLForFileInStore)(Class, SEL, id, id) = NULL;
static NSURL *hooked_fileURLForFileInStore(Class cls, SEL sel, id name, id store) {
    (void)cls; (void)sel;
    NSURL *dir = syntheticStoreURLTokens(tokenFromId(store), nil);
    NSString *path = [dir.path stringByAppendingPathComponent:tokenFromId(name)];
    mkdirp([path stringByDeletingLastPathComponent]);
    return [NSURL fileURLWithPath:path isDirectory:NO];
}

// + fileURLForFileNamed:inStore:ofType:
static NSURL *(*orig_fileURLForFileInStoreOfType)(Class, SEL, id, id, NSInteger) = NULL;
static NSURL *hooked_fileURLForFileInStoreOfType(Class cls, SEL sel, id name, id store, NSInteger type) {
    (void)cls; (void)sel;
    NSURL *dir = syntheticStoreURLTokens(tokenFromId(store),
                                         [NSString stringWithFormat:@"ty%ld", (long)type]);
    NSString *path = [dir.path stringByAppendingPathComponent:tokenFromId(name)];
    mkdirp([path stringByDeletingLastPathComponent]);
    return [NSURL fileURLWithPath:path isDirectory:NO];
}

// + fileURLForFileNamed:inStore:substore:
static NSURL *(*orig_fileURLForFileInStoreSub)(Class, SEL, id, id, id) = NULL;
static NSURL *hooked_fileURLForFileInStoreSub(Class cls, SEL sel, id name, id store, id sub) {
    (void)cls; (void)sel;
    NSURL *dir = syntheticStoreURLTokens(tokenFromId(store), tokenFromId(sub));
    NSString *path = [dir.path stringByAppendingPathComponent:tokenFromId(name)];
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
        // LINE 类可能稍后才加载
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            Class c2 = NSClassFromString(@"LineFileManager");
            if (!c2) {
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

    swizzleClassMethod(cls, @selector(privateFileStoresAreAccessible),
                       (IMP)hooked_privateFileStoresAreAccessible,
                       (void **)&orig_privateFileStoresAreAccessible);

    swizzleClassMethod(cls, @selector(fileURLForStoreType:),
                       (IMP)hooked_fileURLForStoreType,
                       (void **)&orig_fileURLForStoreType);

    swizzleClassMethod(cls, @selector(fileURLForStore:),
                       (IMP)hooked_fileURLForStore,
                       (void **)&orig_fileURLForStore);

    swizzleClassMethod(cls, @selector(fileURLForStore:ofType:),
                       (IMP)hooked_fileURLForStoreOfType,
                       (void **)&orig_fileURLForStoreOfType);

    swizzleClassMethod(cls, @selector(fileURLForStore:substore:),
                       (IMP)hooked_fileURLForStoreSubstore,
                       (void **)&orig_fileURLForStoreSubstore);

    swizzleClassMethod(cls, @selector(fileURLForFileNamed:inStore:),
                       (IMP)hooked_fileURLForFileInStore,
                       (void **)&orig_fileURLForFileInStore);

    swizzleClassMethod(cls, @selector(fileURLForFileNamed:inStore:ofType:),
                       (IMP)hooked_fileURLForFileInStoreOfType,
                       (void **)&orig_fileURLForFileInStoreOfType);

    swizzleClassMethod(cls, @selector(fileURLForFileNamed:inStore:substore:),
                       (IMP)hooked_fileURLForFileInStoreSub,
                       (void **)&orig_fileURLForFileInStoreSub);

    NSLog(@"[LineAccount] LineFileManager hooks OK");
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
    sub.text = @"每个账号独立登录与聊天数据";
    sub.textColor = [UIColor colorWithWhite:1 alpha:0.85];
    sub.font = [UIFont systemFontOfSize:15];
    sub.textAlignment = NSTextAlignmentCenter;
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
        NSString *db = [slotHomePath(i) stringByAppendingPathComponent:@"Library/Application Support/Messages/Line.sqlite"];
        NSString *mark = ([[NSFileManager defaultManager] fileExistsAtPath:flag] ||
                          [[NSFileManager defaultManager] fileExistsAtPath:db])
                         ? @"已有数据" : @"新建容器";
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

static IMP orig_didFinishLaunching = NULL;
static id g_deferredDelegate = nil;
static UIApplication *g_deferredApp = nil;
static NSDictionary *g_deferredOpts = nil;
static BOOL g_launchDeferred = NO;
static BOOL g_launchResumed = NO;

static void hideLINEWindows(void);
static void showAccountPicker(void);

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

    NSMutableDictionary *meta = loadMeta();
    meta[@"selectedSlot"] = @(slot);
    meta[@"pendingEnter"] = @NO;
    saveMeta(meta);

    // 先切沙盒，再放行 LINE（无需重启进程）
    // 注意：不要在登录前装 LineFileManager hooks——
    // privateFileStoresAreAccessible=YES 会让点「登入」时走坏路径 → libobjc AV
    g_selectedSlot = slot;
    NSLog(@"[LineAccount] selected slot %ld — continue without restart (LFM hooks deferred until stable)", (long)slot);
    resumeLINELaunch();
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
        return YES; // 告诉系统启动成功，实际业务等选完再跑
    }

    if (orig_didFinishLaunching) {
        return ((BOOL(*)(id,SEL,UIApplication*,NSDictionary*))orig_didFinishLaunching)(self, _cmd, app, opts);
    }
    return YES;
}

static void hookAppDelegate(void) {
    installWindowBlockHook();

    NSArray *names = @[@"AppDelegate", @"LINEAppDelegate", @"NLAppDelegate", @"LineAppDelegate"];
    for (NSString *name in names) {
        Class cls = NSClassFromString(name);
        if (!cls) continue;
        Method m = class_getInstanceMethod(cls, @selector(application:didFinishLaunchingWithOptions:));
        if (m) {
            orig_didFinishLaunching = method_setImplementation(m, (IMP)hooked_didFinishLaunching);
            NSLog(@"[LineAccount] hooked %@", name);
            return;
        }
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_needPicker) showAccountPicker();
    });
}

__attribute__((constructor))
static void line_account_init(void) {
    NSLog(@"[LineAccount] ========================================");
    NSLog(@"[LineAccount] multi-account dylib loaded (no-restart mode)");
    NSLog(@"[LineAccount] ========================================");

    // 每次冷启动都先选账号；选完再进沙盒，不杀进程
    // 清理旧版 pending 重启标记
    NSMutableDictionary *meta = loadMeta();
    if (meta[@"pendingEnter"]) {
        meta[@"pendingEnter"] = @NO;
        saveMeta(meta);
    }

    g_needPicker = YES;
    g_blockLINEUI = YES;
    g_selectedSlot = -1; // 选择页前不 remap，避免提前进 account_0 / LineStores
    g_launchResumed = NO;
    mkdirp(slotsRootPath());

    installRuntimeHooks();
    installKeychainHooks();
    hookAppDelegate();

    dispatch_async(dispatch_get_main_queue(), ^{
        showAccountPicker();
    });
}
