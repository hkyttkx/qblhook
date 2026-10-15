// QBLHook.m v7 — VC 树抓真身 + 精准 hook
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <UIKit/UIKit.h>

static NSMutableString *gRep = nil;
static Class gHackCls = nil;
static BOOL  gSwitched = NO;

static BOOL isAppClass(Class c) {
    const char *img = class_getImageName(c);
    if (!img) return NO;
    return strstr(img, "QBL") != NULL;
}
static id msgId(id o, SEL s) { return ((id(*)(id,SEL))objc_msgSend)(o, s); }
static BOOL fake_BOOL_YES(id self, SEL _cmd) { return YES; }
static void fake_sendLogin_block(id self, SEL _cmd, id arg, void *blk) {
    if (blk) { void (^b)(BOOL) = (__bridge void (^)(BOOL))blk; b(YES); }
}

static UIWindow *keyWin(void) {
    UIWindow *w = nil;
    for (UIWindow *x in [UIApplication sharedApplication].windows)
        if (x.isKeyWindow) w = x;
    return w ?: [UIApplication sharedApplication].windows.firstObject;
}

static void collectVC(UIViewController *vc, NSMutableArray *out, int depth) {
    if (!vc || depth > 6) return;
    NSString *n = NSStringFromClass([vc class]);
    if (n && ![out containsObject:n]) [out addObject:n];
    for (UIViewController *c in vc.childViewControllers) collectVC(c, out, depth+1);
    collectVC(vc.presentedViewController, out, depth+1);
    collectVC(vc.parentViewController, out, depth+1);
}

static UIViewController *findInst(UIViewController *vc, int depth) {
    if (!vc || depth > 6) return nil;
    if (gHackCls && [vc isKindOfClass:gHackCls]) return vc;
    for (UIViewController *c in vc.childViewControllers) {
        UIViewController *r = findInst(c, depth+1);
        if (r) return r;
    }
    if (vc.presentedViewController) {
        UIViewController *r = findInst(vc.presentedViewController, depth+1);
        if (r) return r;
    }
    return nil;
}

static void scan(void) {
    int n = objc_getClassList(NULL,0);
    Class *list = (Class *)malloc(sizeof(Class)*n);
    objc_getClassList(list,n);
    for (int i=0;i<n;i++){
        Class c = list[i];
        if (!isAppClass(c)) continue;
        @try {
            Method h = class_getInstanceMethod(c, sel_registerName("hackViewController"));
            if (h && !gHackCls) gHackCls = c;
        } @catch(NSException *e){}
    }
    free(list);
}

static void doHooks(void) {
    int n = objc_getClassList(NULL,0);
    Class *list = (Class *)malloc(sizeof(Class)*n);
    objc_getClassList(list,n);
    for (int i=0;i<n;i++){
        Class c = list[i];
        if (!isAppClass(c)) continue;
        @try {
            Method m = class_getInstanceMethod(c, sel_registerName("isHackActive"));
            if (m) {
                const char *e = method_getTypeEncoding(m);
                if (e && strcmp(e,"B16@0:8")==0 && method_getImplementation(m)!=(IMP)fake_BOOL_YES) {
                    method_setImplementation(m,(IMP)fake_BOOL_YES);
                    [gRep appendFormat:@"hooked isHackActive <%s>\n", class_getName(c)];
                }
            }
            Method sm = class_getInstanceMethod(c, sel_registerName("sendLogin:completion:"));
            if (sm && method_getImplementation(sm)!=(IMP)fake_sendLogin_block) {
                method_setImplementation(sm,(IMP)fake_sendLogin_block);
                [gRep appendFormat:@"hooked sendLogin:completion: <%s>\n", class_getName(c)];
            }
        } @catch(NSException *e){}
    }
    free(list);
}

static void doPresent(void) {
    UIWindow *win = keyWin();
    UIViewController *rt = win.rootViewController;
    UIViewController *ins = findInst(rt, 0);
    if (!ins) {
        id o = msgId((id)gHackCls, sel_registerName("alloc"));
        ins = msgId(o, sel_registerName("init"));
        [gRep appendFormat:@"fallback alloc/init -> %@\n", ins];
    } else {
        [gRep appendFormat:@"found in tree: %@\n", NSStringFromClass([ins class])];
    }
    if (!ins) { [gRep appendString:@"no inst\n"]; return; }
    SEL hs = NSSelectorFromString(@"hackViewController");
    if (![ins respondsToSelector:hs]) { [gRep appendString:@"no hackViewController\n"]; return; }
    id vc = msgId(ins, hs);
    [gRep appendFormat:@"hackVC=%@\n", vc];
    if (vc && [vc isKindOfClass:[UIViewController class]]) {
        win.rootViewController = vc;
        [win makeKeyAndVisible];
        gSwitched = YES;
        [gRep appendString:@"SWITCHED!\n"];
    } else {
        [gRep appendString:@"hackViewController returned nil\n"];
    }
}

static void showReport(void) {
    UIWindow *w = keyWin();
    UIViewController *root = w.rootViewController;
    NSMutableArray *tree = [NSMutableArray array];
    collectVC(root, tree, 0);
    [gRep appendFormat:@"\nroot=%@\n", NSStringFromClass([root class])];
    [gRep appendFormat:@"VC树=%@\n", [tree componentsJoinedByString:@"|"]];
    [gRep appendFormat:@"hackCls=%s\n", gHackCls?class_getName(gHackCls):"nil"];

    dispatch_async(dispatch_get_main_queue(), ^{
        UIViewController *r = keyWin().rootViewController;
        while (r.presentedViewController) r = r.presentedViewController;
        UIAlertController *al = [UIAlertController alertControllerWithTitle:@"QBL v7"
                                    message:gRep preferredStyle:UIAlertControllerStyleAlert];
        [al addAction:[UIAlertAction actionWithTitle:@"进入主界面"
                          style:UIAlertActionStyleDefault handler:^(UIAlertAction *a){
            [gRep appendString:@"\n-- tryPresent --\n"];
            doPresent();
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.6*NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                UIViewController *r2 = keyWin().rootViewController;
                while (r2.presentedViewController) r2 = r2.presentedViewController;
                UIAlertController *al2 = [UIAlertController
                    alertControllerWithTitle:(gSwitched?@"成功":@"结果") message:gRep
                             preferredStyle:UIAlertControllerStyleAlert];
                [al2 addAction:[UIAlertAction actionWithTitle:@"OK"
                                    style:UIAlertActionStyleDefault handler:nil]];
                [r2 presentViewController:al2 animated:YES completion:nil];
            });
        }]];
        [al addAction:[UIAlertAction actionWithTitle:@"Cancel"
                          style:UIAlertActionStyleCancel handler:nil]];
        [r presentViewController:al animated:YES completion:nil];
    });
}

__attribute__((constructor))
static void init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(2.5*NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        gRep = [NSMutableString string];
        [gRep appendString:@"== QBL v7 ==\n"];
        scan();
        doHooks();
        showReport();
    });
}
