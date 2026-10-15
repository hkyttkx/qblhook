// AQHook — 绕过 AQREH dylib 的检测（代理/VPN/签名/白名单/nonce）
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <UIKit/UIKit.h>

static NSMutableString *gRep = nil;
static BOOL retYES(id s, SEL c) { return YES; }
static BOOL retNO (id s, SEL c) { return NO; }
static BOOL retYES1(id s, SEL c, id a) { return YES; }
static BOOL retNO1 (id s, SEL c, id a) { return NO; }
static BOOL retYES2(id s, SEL c, id a, id b) { return YES; }
static BOOL retNO2 (id s, SEL c, id a, id b) { return NO; }

// 只处理非系统 image 的类，避免破坏 NSProxy / NSObject 语义
static BOOL isTargetClass(Class c) {
    const char *img = class_getImageName(c);
    if (!img) return NO;
    if (strstr(img, "/System/")) return NO;
    if (strstr(img, "/usr/lib")) return NO;
    return YES;
}

static void run(void) {
    gRep = [NSMutableString string];
    [gRep appendString:@"== AQ Hook ==\n"];

    struct { const char *name; IMP imp; } targets[] = {
        {"isProxy",                          (IMP)retNO},     // 代理检测 -> NO
        {"isAllowedAuthURL:",                (IMP)retYES1},   // URL 白名单 -> YES
        {"verifyResponseSignature:forData:", (IMP)retYES2},   // 响应签名 -> YES
        {"isNonceUsed:",                     (IMP)retNO1},    // nonce 已用过 -> NO
        {NULL, NULL}
    };

    int n = objc_getClassList(NULL, 0);
    Class *list = (Class *)malloc(sizeof(Class) * n);
    objc_getClassList(list, n);
    int cnt = 0;

    for (int i = 0; i < n; i++) {
        Class c = list[i];
        if (!isTargetClass(c)) continue;
        @try {
            for (int k = 0; targets[k].name; k++) {
                SEL sel = sel_registerName(targets[k].name);
                Method m = class_getInstanceMethod(c, sel);
                if (!m) continue;
                const char *enc = method_getTypeEncoding(m);
                [gRep appendFormat:@"<%s> %s [%s]\n", class_getName(c), targets[k].name, enc ? enc : "?"];
                cnt++;
                if (method_getImplementation(m) != targets[k].imp)
                    method_setImplementation(m, targets[k].imp);
            }
        } @catch (NSException *e) {}
    }
    free(list);
    [gRep appendFormat:@"\n命中 %d 个方法\n", cnt];

    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *win = nil;
        for (UIWindow *w in [UIApplication sharedApplication].windows)
            if (w.isKeyWindow) win = w;
        if (!win) win = [UIApplication sharedApplication].windows.firstObject;
        UIViewController *root = win.rootViewController;
        while (root.presentedViewController) root = root.presentedViewController;
        if (!root) return;
        UIAlertController *al = [UIAlertController alertControllerWithTitle:@"AQ Hook"
                                    message:gRep preferredStyle:UIAlertControllerStyleAlert];
        [al addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [root presentViewController:al animated:YES completion:nil];
    });
}

__attribute__((constructor))
static void init(void) {
    NSLog(@"[AQHook] loaded");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.5*NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ run(); });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0*NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ run(); });
}
