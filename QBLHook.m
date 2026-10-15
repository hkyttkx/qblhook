// QBLHook.m v5 — 运行时诊断弹窗 + 尝试 hook 校验逻辑
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <UIKit/UIKit.h>

static BOOL fakeYES(id self, SEL _cmd) { return YES; }

static const char *kTargets[] = {
    "handleLoginLogic", "handleCheckLogic", "hackViewController",
    "sendLogin:", "sendLogin:completion:", "sendLoginMessage:completion:",
    "startLoginFlow", "switchToLoginScreen",
    "validKey", "isHackActive", "sharedLoginView", "loginViewController",
    "checkKey", "verifyKey", "handleBuyLogic", NULL
};

static void run(void) {
    NSMutableString *rep = [NSMutableString string];
    [rep appendString:@"== QBL Dump ==\n"];

    int n = objc_getClassList(NULL, 0);
    Class *list = (Class *)malloc(sizeof(Class) * n);
    objc_getClassList(list, n);

    int lines = 0;
    for (int i = 0; i < n; i++) {
        Class c = list[i];
        @try {
            for (int k = 0; kTargets[k]; k++) {
                SEL sel = sel_registerName(kTargets[k]);
                Method m = class_getInstanceMethod(c, sel);
                if (!m) continue;
                const char *enc = method_getTypeEncoding(m);
                [rep appendFormat:@"<%s> %s [%s]\n",
                    class_getName(c), kTargets[k], enc ? enc : "?"];
                lines++;

                // 尝试 hook：返回 BOOL 的校验方法 -> YES
                if (enc && (strcmp(enc, "c@:") == 0 || strcmp(enc, "B@:") == 0)) {
                    if (strcmp(kTargets[k], "handleCheckLogic") == 0 ||
                        strcmp(kTargets[k], "handleLoginLogic") == 0 ||
                        strcmp(kTargets[k], "checkKey") == 0 ||
                        strcmp(kTargets[k], "verifyKey") == 0) {
                        if (method_getImplementation(m) != (IMP)fakeYES) {
                            method_setImplementation(m, (IMP)fakeYES);
                            [rep appendString:@"   -> HOOKED to YES\n"];
                        }
                    }
                }
            }
        } @catch (NSException *e) {}
        if (lines > 60) { [rep appendString:@"...(truncated)\n"]; break; }
    }
    free(list);

    if (lines == 0) [rep appendString:@"(没有匹配的类/方法)\n"];

    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *win = nil;
        for (UIWindow *w in [UIApplication sharedApplication].windows) {
            if (w.isKeyWindow) { win = w; break; }
        }
        if (!win) win = [UIApplication sharedApplication].windows.firstObject;
        UIViewController *root = win.rootViewController;
        while (root.presentedViewController) root = root.presentedViewController;
        if (!root) return;

        UIAlertController *al = [UIAlertController
            alertControllerWithTitle:@"QBL Dump"
                             message:rep
                      preferredStyle:UIAlertControllerStyleAlert];
        [al addAction:[UIAlertAction actionWithTitle:@"OK"
                                                style:UIAlertActionStyleDefault
                                              handler:nil]];
        [root presentViewController:al animated:YES completion:nil];
    });
}

__attribute__((constructor))
static void init(void) {
    NSLog(@"[QBLHook] v5 loaded");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.5*NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ run(); });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0*NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ run(); });
}
