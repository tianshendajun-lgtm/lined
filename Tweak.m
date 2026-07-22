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

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Wunused-function"

#define ACCOUNT_COUNT 4
#define SLOT_DIR_NAME @"LineAccountSlots"
#define SELECTED_SLOT_KEY @"LineAccount.SelectedSlot"
#define PENDING_ENTER_KEY @"LineAccount.PendingEnter" // 选完杀进程后，下次启动直接进该槽

static NSInteger g_selectedSlot = -1;   // 1..4
static BOOL g_pickerShown = NO;
static BOOL g_hooksInstalled = NO;

#pragma mark - 路径工具

static NSString *slotsRootPath(void) {
    NSString *home = NSHomeDirectory();
    return [home stringByAppendingPathComponent:SLOT_DIR_NAME];
}

static NSString *slotHomePath(NSInteger slot) {
    return [slotsRootPath() stringByAppendingPathComponent:
            [NSString stringWithFormat:@"account_%ld", (long)slot]];
}

static void ensureSlotDirectories(NSInteger slot) {
    NSArray *subs = @[
        @"Documents",
        @"Library/Preferences",
        @"Library/Caches",
        @"Library/Application Support",
        @"tmp",
        @"AppGroup/group.com.linecorp.line",
        @"AppGroup/group.com.linecorp.Line.encrypted.app",
        @"AppGroup/group.share.com.linecorp.line",
        @"AppGroup/group.com.linecorp.Line.encrypted.share",
    ];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *root = slotHomePath(slot);
    for (NSString *sub in subs) {
        NSString *path = [root stringByAppendingPathComponent:sub];
        if (![fm fileExistsAtPath:path]) {
            [fm createDirectoryAtPath:path withIntermediateDirectories:YES attributes:nil error:nil];
        }
    }
}

static NSString *slotKeyPrefix(NSInteger slot) {
    return [NSString stringWithFormat:@"line.slot.%ld.", (long)slot];
}

static BOOL pathNeedsRemap(NSString *path) {
    if (path.length == 0) return NO;
    if ([path containsString:SLOT_DIR_NAME]) return NO;
    NSString *home = NSHomeDirectory();
    if ([path hasPrefix:home]) return YES;
    // App Group 常见路径片段
    if ([path containsString:@"/Library/Group Containers/"] ||
        [path containsString:@"group.com.linecorp"]) {
        return YES;
    }
    return NO;
}

static NSString *remapPath(NSString *path) {
    if (g_selectedSlot < 1 || !pathNeedsRemap(path)) return path;

    NSString *home = NSHomeDirectory();
    NSString *slotHome = slotHomePath(g_selectedSlot);

    if ([path hasPrefix:home]) {
        NSString *rel = [path substringFromIndex:home.length];
        if ([rel hasPrefix:@"/"]) rel = [rel substringFromIndex:1];
        // 不要把槽位根目录自己再映射进去
        if ([rel hasPrefix:SLOT_DIR_NAME]) return path;
        return [slotHome stringByAppendingPathComponent:rel];
    }

    // Group Containers → slot AppGroup
    NSRange r = [path rangeOfString:@"/Library/Group Containers/"];
    if (r.location != NSNotFound) {
        NSString *after = [path substringFromIndex:r.location + r.length];
        // after: group.com.linecorp.line/...
        return [[slotHome stringByAppendingPathComponent:@"AppGroup"]
                stringByAppendingPathComponent:after];
    }
    return path;
}

#pragma mark - Keychain 字典改写

static CFDictionaryRef rewriteKeychainQuery(CFDictionaryRef query, BOOL forWrite) {
    if (!query || g_selectedSlot < 1) return query;

    NSDictionary *orig = (__bridge NSDictionary *)query;
    NSMutableDictionary *m = [orig mutableCopy];
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
    if (g_selectedSlot >= 1 && groupId.length > 0) {
        NSString *path = [[slotHomePath(g_selectedSlot)
                           stringByAppendingPathComponent:@"AppGroup"]
                          stringByAppendingPathComponent:groupId];
        [[NSFileManager defaultManager] createDirectoryAtPath:path
                                  withIntermediateDirectories:YES
                                                   attributes:nil
                                                        error:nil];
        return [NSURL fileURLWithPath:path isDirectory:YES];
    }
    return orig_containerURL(self, _cmd, groupId);
}

static BOOL hooked_createDirectory(id self, SEL _cmd, NSString *path, BOOL intermediates, NSDictionary *attr, NSError **err) {
    return ((BOOL(*)(id,SEL,NSString*,BOOL,NSDictionary*,NSError**))orig_createDirectory)
        (self, _cmd, remapPath(path), intermediates, attr, err);
}

static BOOL hooked_fileExists(id self, SEL _cmd, NSString *path) {
    return ((BOOL(*)(id,SEL,NSString*))orig_fileExists)(self, _cmd, remapPath(path));
}

static NSArray *hooked_contentsOfDirectory(id self, SEL _cmd, NSString *path, NSError **err) {
    return ((NSArray*(*)(id,SEL,NSString*,NSError**))orig_contentsOfDirectory)
        (self, _cmd, remapPath(path), err);
}

static BOOL hooked_removeItem(id self, SEL _cmd, NSString *path, NSError **err) {
    return ((BOOL(*)(id,SEL,NSString*,NSError**))orig_removeItem)(self, _cmd, remapPath(path), err);
}

static BOOL hooked_copyItem(id self, SEL _cmd, NSString *src, NSString *dst, NSError **err) {
    return ((BOOL(*)(id,SEL,NSString*,NSString*,NSError**))orig_copyItem)
        (self, _cmd, remapPath(src), remapPath(dst), err);
}

static BOOL hooked_moveItem(id self, SEL _cmd, NSString *src, NSString *dst, NSError **err) {
    return ((BOOL(*)(id,SEL,NSString*,NSString*,NSError**))orig_moveItem)
        (self, _cmd, remapPath(src), remapPath(dst), err);
}

static BOOL hooked_createFile(id self, SEL _cmd, NSString *path, NSData *data, NSDictionary *attr) {
    return ((BOOL(*)(id,SEL,NSString*,NSData*,NSDictionary*))orig_createFile)
        (self, _cmd, remapPath(path), data, attr);
}

static NSArray *hooked_URLsForDirectory(id self, SEL _cmd, NSSearchPathDirectory dir, NSSearchPathDomainMask domain) {
    NSArray *urls = ((NSArray*(*)(id,SEL,NSSearchPathDirectory,NSSearchPathDomainMask))orig_URLsForDirectory)
        (self, _cmd, dir, domain);
    if (g_selectedSlot < 1) return urls;
    NSMutableArray *out = [NSMutableArray array];
    for (NSURL *u in urls) {
        NSString *p = remapPath(u.path);
        [out addObject:[NSURL fileURLWithPath:p isDirectory:YES]];
    }
    return out;
}

static void installRuntimeHooks(void) {
    if (g_hooksInstalled) return;
    g_hooksInstalled = YES;

    // Keychain
    orig_SecItemAdd = (SecItemAdd_t)dlsym(RTLD_DEFAULT, "SecItemAdd");
    orig_SecItemCopyMatching = (SecItemCopyMatching_t)dlsym(RTLD_DEFAULT, "SecItemCopyMatching");
    orig_SecItemUpdate = (SecItemUpdate_t)dlsym(RTLD_DEFAULT, "SecItemUpdate");
    orig_SecItemDelete = (SecItemDelete_t)dlsym(RTLD_DEFAULT, "SecItemDelete");

    // 用 fishhook 风格不可直接替换导出符号时，优先用 method swizzle；
    // 这里对 Security C API 采用简单的函数指针保存 + 后续可用 substrate/fishhook。
    // 非越狱注入场景：用 ObjC 层 NSFileManager + App Group 覆盖主路径；
    // Keychain 用 runtime interpose 较难，下面用 dlsym 记录，真正替换需 fishhook。
    // 为在无第三方库时尽量可用，Keychain 改写放到 ObjC 包装层；此处先装 FileManager。

    Class fm = [NSFileManager class];
    Method m;

    m = class_getInstanceMethod(fm, @selector(createDirectoryAtPath:withIntermediateDirectories:attributes:error:));
    if (m) orig_createDirectory = method_setImplementation(m, (IMP)hooked_createDirectory);

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

    m = class_getInstanceMethod(fm, @selector(URLsForDirectory:inDomains:));
    if (m) orig_URLsForDirectory = method_setImplementation(m, (IMP)hooked_URLsForDirectory);

    m = class_getInstanceMethod(fm, @selector(containerURLForSecurityApplicationGroupIdentifier:));
    if (m) {
        orig_containerURL = (ContainerURL_t)method_getImplementation(m);
        method_setImplementation(m, (IMP)hooked_containerURL);
    }

    NSLog(@"[LineAccount] FileManager / AppGroup hooks installed");
}

#pragma mark - fishhook Keychain（内嵌精简版）

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <string.h>
#include <stdlib.h>

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
                    if (rebindings[j].replaced && bindings[i] != rebindings[j].replacement) {
                        *(rebindings[j].replaced) = bindings[i];
                    }
                    bindings[i] = rebindings[j].replacement;
                    break;
                }
            }
        }
    }
    return 0;
}

static void rebind_symbols_for_image(const struct mach_header *header, intptr_t slide,
                                     struct rebinding rebindings[], size_t count) {
    Dl_info info;
    if (dladdr(header, &info) == 0) return;

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
            for (uint32_t j = 0; j < curSeg->nsects; j++) {
                section_t *sect = (section_t *)(cur + sizeof(segment_command_t)) + j;
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
    struct rebinding rebs[4] = {
        {"SecItemAdd", (void *)hooked_SecItemAdd, (void **)&orig_SecItemAdd},
        {"SecItemCopyMatching", (void *)hooked_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching},
        {"SecItemUpdate", (void *)hooked_SecItemUpdate, (void **)&orig_SecItemUpdate},
        {"SecItemDelete", (void *)hooked_SecItemDelete, (void **)&orig_SecItemDelete},
    };
    rebind_symbols(rebs, 4);
    NSLog(@"[LineAccount] Keychain hooks installed");
}

#pragma mark - 账号选择 UI

@interface LineAccountPickerController : UIViewController
@end

@implementation LineAccountPickerController

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
        NSString *mark = [[NSFileManager defaultManager]
                          fileExistsAtPath:[slotHomePath(i) stringByAppendingPathComponent:@"Library/Preferences"]]
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
    NSInteger slot = sender.tag;
    ensureSlotDirectories(slot);

    // 必须在设置 g_selectedSlot 之前写入，否则 Preferences 会被 remap 到槽位目录
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud setInteger:slot forKey:SELECTED_SLOT_KEY];
    [ud setBool:YES forKey:PENDING_ENTER_KEY];
    [ud synchronize];

    g_selectedSlot = slot;
    NSLog(@"[LineAccount] selected account slot %ld, restarting...", (long)slot);
    // 冷启动最稳：选完后杀进程，下次带槽位启动（避免 LINE 已初始化串库）
    exit(0);
}

@end

static UIWindow *pickerWindow = nil;

static void showAccountPicker(void) {
    if (g_pickerShown) return;
    g_pickerShown = YES;

    dispatch_async(dispatch_get_main_queue(), ^{
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

        if (@available(iOS 13.0, *)) {
            if (scene) {
                pickerWindow = [[UIWindow alloc] initWithWindowScene:scene];
            }
        }
        if (!pickerWindow) {
            pickerWindow = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
        }
        pickerWindow.windowLevel = UIWindowLevelAlert + 100;
        pickerWindow.rootViewController = [LineAccountPickerController new];
        pickerWindow.hidden = NO;
        [pickerWindow makeKeyAndVisible];
        NSLog(@"[LineAccount] picker shown");
    });
}

#pragma mark - 启动逻辑

static void decideLaunchFlow(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSInteger saved = [ud integerForKey:SELECTED_SLOT_KEY];
    BOOL pending = [ud boolForKey:PENDING_ENTER_KEY];

    // 选完账号后的第二次启动：直接进入容器，不弹选择页
    if (pending && saved >= 1 && saved <= ACCOUNT_COUNT) {
        g_selectedSlot = saved;
        ensureSlotDirectories(saved);
        [ud setBool:NO forKey:PENDING_ENTER_KEY];
        [ud synchronize];
        NSLog(@"[LineAccount] enter slot %ld", (long)saved);
        return;
    }

    // 每次正常打开 LINE：先显示账号首页
    showAccountPicker();
}

static IMP orig_didFinishLaunching = NULL;

static BOOL hooked_didFinishLaunching(id self, SEL _cmd, UIApplication *app, NSDictionary *opts) {
    BOOL r = YES;
    if (orig_didFinishLaunching) {
        r = ((BOOL(*)(id,SEL,UIApplication*,NSDictionary*))orig_didFinishLaunching)(self, _cmd, app, opts);
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        decideLaunchFlow();
    });
    return r;
}

static void hookAppDelegate(void) {
    // 尝试 hook 常见 AppDelegate
    NSArray *names = @[@"AppDelegate", @"LINEAppDelegate", @"NLAppDelegate"];
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

    // 兜底：延迟显示
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        decideLaunchFlow();
    });
}

__attribute__((constructor))
static void line_account_init(void) {
    NSLog(@"[LineAccount] ========================================");
    NSLog(@"[LineAccount] multi-account dylib loaded");
    NSLog(@"[LineAccount] ========================================");

    installRuntimeHooks();
    installKeychainHooks();

    // 尽早读取待进入槽位，让 LINE 初始化前就开始 remap
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSInteger saved = [ud integerForKey:SELECTED_SLOT_KEY];
    if ([ud boolForKey:PENDING_ENTER_KEY] && saved >= 1 && saved <= ACCOUNT_COUNT) {
        g_selectedSlot = saved;
        ensureSlotDirectories(saved);
    }

    hookAppDelegate();
}
