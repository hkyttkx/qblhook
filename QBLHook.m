// QBLHook.m — 授权校验 bypass
// 纯 Objective-C runtime，Xcode clang 直接编译

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

static BOOL fake_TRUE(id self, SEL _cmd) { return YES; }

static void hookAll(void) {
    int n = objc_getClassList(NULL, 0);
    if (n <= 0) return;
    Class *list = (Class *)malloc(sizeof(Class) * n);
    if (!list) return;
    objc_getClassList(list, n);

    const char *names[] = { "validKey", "isHackActive", "isValidKey", "activated",
                            "isActivated", "isVip", "isPremium", NULL };

    for (int i = 0; i < n; i++) {
        Class c = list[i];

        for (int k = 0; names[k]; k++) {
            SEL sel = sel_registerName(names[k]);
            Method m = class_getInstanceMethod(c, sel);
            if (!m) continue;
            if (method_getImplementation(m) == (IMP)fake_TRUE) continue;
            method_setImplementation(m, (IMP)fake_TRUE);
            NSLog(@"[QBLHook] hooked -[%s %s]", class_getName(c), names[k]);
        }

        // setter：永远置 YES
        Method sm = class_getInstanceMethod(c, sel_registerName("setValidKey:"));
        if (sm) method_setImplementation(sm, (IMP)fake_TRUE);
    }
    free(list);
}

__attribute__((constructor))
static void QBLHookInit(void) {
    NSLog(@"[QBLHook] loaded");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        hookAll();
        NSLog(@"[QBLHook] hook pass 1 done");
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        hookAll();
        NSLog(@"[QBLHook] hook pass 2 done");
    });
}
