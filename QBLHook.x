// QBLHook.x — 让本地授权校验恒真
// 纯 runtime API，不依赖 substrate/CydiaSubstrate，GitHub 上可直接编

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

static BOOL fake_TRUE(id self, SEL _cmd) { return YES; }

static void hookAll(void) {
    int n = objc_getClassList(NULL, 0);
    if (n <= 0) return;
    Class *list = (Class *)malloc(sizeof(Class) * n);
    if (!list) return;
    objc_getClassList(list, n);

    const char *names[] = { "validKey", "isHackActive", "isValidKey", "activated", NULL };

    for (int i = 0; i < n; i++) {
        Class c = list[i];
        const char *cname = class_getName(c);

        for (int k = 0; names[k]; k++) {
            SEL sel = sel_registerName(names[k]);
            Method m = class_getInstanceMethod(c, sel);
            if (!m) continue;

            IMP cur = method_getImplementation(m);
            if (cur == (IMP)fake_TRUE) continue;

            method_setImplementation(m, (IMP)fake_TRUE);
            NSLog(@"[QBLHook] hooked -[%s %s]", cname, names[k]);
        }

        // setter 也顶掉，防它把状态写回 NO
        SEL setter = sel_registerName("setValidKey:");
        Method sm = class_getInstanceMethod(c, setter);
        if (sm) {
            method_setImplementation(sm, (IMP)fake_TRUE);
        }
    }
    free(list);
}

__attribute__((constructor))
static void QBLHookInit(void) {
    NSLog(@"[QBLHook] loaded");

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ hookAll(); });

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        hookAll();
        NSLog(@"[QBLHook] hook pass done");
    });
}
