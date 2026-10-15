// QBLHook.m v2 — 授权校验 bypass（修正版）
// 关键修正：
//   1. 去掉 setter hook（签名不匹配 + 无必要）
//   2. 用 method_setImplementation 前先检查，避免重复
//   3. 不碰任何可能带 ptrauth 的内部方法

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

static BOOL fake_TRUE(id self, SEL _cmd) { return YES; }

static void hookAll(void) {
    int n = objc_getClassList(NULL, 0);
    if (n <= 0) return;
    Class *list = (Class *)malloc(sizeof(Class) * n);
    if (!list) return;
    objc_getClassList(list, n);

    // 只 hook 这些明确返回 BOOL 的属性 getter
    const char *names[] = {
        "validKey", "isHackActive", "isValidKey", "activated",
        "isActivated", "isVip", "isPremium", "isPro", NULL
    };

    for (int i = 0; i < n; i++) {
        Class c = list[i];

        for (int k = 0; names[k]; k++) {
            SEL sel = sel_registerName(names[k]);
            Method m = class_getInstanceMethod(c, sel);
            if (!m) continue;

            const char *enc = method_getTypeEncoding(m);
            // 只处理返回 BOOL/char 的，且无额外参数
            // 编码形如 "c@:" 或 "B@:"
            if (!enc || (enc[0] != 'c' && enc[0] != 'B')) continue;
            if (strcmp(enc, "c@:") != 0 && strcmp(enc, "B@:") != 0) continue;

            IMP cur = method_getImplementation(m);
            if (cur == (IMP)fake_TRUE) continue;

            @try {
                method_setImplementation(m, (IMP)fake_TRUE);
                NSLog(@"[QBLHook] hooked -[%s %s]", class_getName(c), names[k]);
            } @catch (NSException *e) {
                NSLog(@"[QBLHook] hook fail %s %s: %@", class_getName(c), names[k], e);
            }
        }
    }
    free(list);
}

__attribute__((constructor))
static void QBLHookInit(void) {
    NSLog(@"[QBLHook] loaded");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        hookAll();
        NSLog(@"[QBLHook] pass1 done");
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        hookAll();
        NSLog(@"[QBLHook] pass2 done");
    });
}
