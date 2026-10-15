// QBLHook.m v6 — image 归属过滤 + 主动进入主界面
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <UIKit/UIKit.h>

static NSMutableString *gRep = nil;
static Class gHackCls = nil;
static id    gHackInst = nil;

static BOOL isAppClass(Class c) {
    const char *img = class_getImageName(c);
    if (!img) return NO;
    return strstr(img, "QBL-ESP") != NULL || strstr(img, "QBL") != NULL;
}

static const char *kTargets[] = {
    "hackViewController", "handleLoginLogic", "handleCheckLogic",
    "sharedLoginView", "loginViewController", "sendLogin:completion:",
    "validKey", "isHackActive", NULL
};

static id msgId(id o, SEL s) { return ((id(*)(id,SEL))objc_msgSend)(o, s); }

static void tryPresent(void) {
    if (!gHackCls) return;
    if (!gHackInst) {
        for (NSString *sn in @[@"sharedInstance", @"sharedManager", @"defaultManager",
                               @"shared", @"mainManager", @"manager"]) {
            SEL s = NSSelectorFromString(sn);
            if ([gHackCls respondsToSelector:s]) {
                gHackInst = msgId(gHackCls, s);
                if (gHackInst) break;
            }
        }
        if (!gHackInst) {
            id o = msgId((id)gHackCls, sel_registerName("alloc"));
            gHackInst = msgId(o, sel_registerName("init"));
        }
    }
    if (!gHackInst) return;
    SEL hs = NSSelectorFromString(@"hackViewController");
    if (![gHackInst respondsToSelector:hs]) return;
    id vc = msgId(gHackInst, hs);
    if (vc && [vc isKindOfClass:[UIViewController class]]) {
        UIWindow *win = nil;
        for (UIWindow *w in [UIApplication sharedApplication].windows)
            if (w.isKeyWindow) win = w;
        if (!win) win = [UIApplication sharedApplication].windows.firstObject;
        win.rootViewController = vc;
        [win makeKeyAndVisible];
        NSLog(@"[QBLHook] presented hack VC: %@", vc);
    }
}

static void run(void) {
    gRep = [NSMutableString string];
    [gRep appendString:@"== QBL v6 ==\n"];
    int n = objc_getClassList(NULL, 0);
    Class *list = (Class *)malloc(sizeof(Class) * n);
    objc_getClassList(list, n);
    int cnt = 0;
    for (int i = 0; i < n; i++) {
        Class c = list[i];
        if (!isAppClass(c)) continue;
        @try {
            for (int k = 0; kTargets[k]; k++) {
                Method m = class_getInstanceMethod(c, sel_registerName(kTargets[k]));
                if (!m) continue;
                const char *enc = method_getTypeEncoding(m);
                [gRep appendFormat:@"<%s> %s [%s]\n", class_getName(c), kTargets[k], enc ? enc : "?"];
                cnt++;
                if (strcmp(kTargets[k], "hackViewController") == 0 && !gHackCls) gHackCls = c;
            }
        } @catch (NSException *e) {}
    }
    free(list);
    [gRep appendFormat:@"\napp类命中=%d\nhackCls=%s\n", cnt,
        gHackCls ? class_getName(gHackCls) : "nil"];

    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *win = nil;
        for (UIWindow *w in [UIApplication sharedApplication].windows)
            if (w.isKeyWindow) win = w;
        if (!win) win = [UIApplication sharedApplication].windows.firstObject;
        UIViewController *root = win.rootViewController;
        while (root.presentedViewController) root = root.presentedViewController;
        if (!root) return;
        UIAlertController *al = [UIAlertController
            alertControllerWithTitle:@"QBL v6" message:gRep
                     preferredStyle:UIAlertControllerStyleAlert];
        [al addAction:[UIAlertAction actionWithTitle:@"进入主界面"
                          style:UIAlertActionStyleDefault
                        handler:^(UIAlertAction *a){ tryPresent(); }]];
        [al addAction:[UIAlertAction actionWithTitle:@"Cancel"
                          style:UIAlertActionStyleCancel handler:nil]];
        [root presentViewController:al animated:YES completion:nil];
    });
}

__attribute__((constructor))
static void init(void) {
    NSLog(@"[QBLHook] v6 loaded");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.5*NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ run(); });
}
