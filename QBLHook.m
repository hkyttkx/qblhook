// QBLHook.m v4 — 枚举定位 + hook 登录逻辑（无 blocks 依赖）
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

static const char *kLoginMethods[] = {
    "handleLoginLogic", "startLoginFlow", "sendLogin:",
    "sendLogin:completion:", "sendLoginMessage:completion:", NULL
};
static const char *kFlagGetters[] = {
    "validKey", "isHackActive", "isValidKey", "activated", "isActivated", NULL
};

static BOOL fake_TRUE(id self, SEL _cmd) { return YES; }
static IMP  s_fakeTrueImp = NULL;

// sendLogin:completion: -> void(id, SEL, id, block)
static void fake_sendLogin_completion(id self, SEL _cmd, id arg, void *completion) {
    NSLog(@"[QBLHook] *intercept* sendLogin:completion: on <%s>", class_getName(object_getClass(self)));
    if (completion) {
        // 调用 block: (BOOL) -> void
        void (^blk)(BOOL) = (__bridge void (^)(BOOL))completion;
        blk(YES);
    }
}

static void scanAndHook(void) {
    int n = objc_getClassList(NULL, 0);
    if (n <= 0) return;
    Class *list = (Class *)malloc(sizeof(Class) * n);
    if (!list) return;
    objc_getClassList(list, n);

    for (int i = 0; i < n; i++) {
        Class c = list[i];
        @try {
            // 1. 报告实现了登录方法的类
            for (int k = 0; kLoginMethods[k]; k++) {
                SEL sel = sel_registerName(kLoginMethods[k]);
                Method m = class_getInstanceMethod(c, sel);
                if (m) {
                    NSLog(@"[QBLHook] FOUND <%s> implements -%s enc=%s",
                          class_getName(c), kLoginMethods[k], method_getTypeEncoding(m));
                }
            }
            // 2. hook sendLogin:completion:
            SEL sc = sel_registerName("sendLogin:completion:");
            Method msc = class_getInstanceMethod(c, sc);
            if (msc) {
                IMP cur = method_getImplementation(msc);
                if (cur != (IMP)fake_sendLogin_completion) {
                    method_setImplementation(msc, (IMP)fake_sendLogin_completion);
                    NSLog(@"[QBLHook] HOOKED sendLogin:completion: on <%s>", class_getName(c));
                }
            }
            // 3. 状态 getter
            for (int k = 0; kFlagGetters[k]; k++) {
                SEL sel = sel_registerName(kFlagGetters[k]);
                Method m = class_getInstanceMethod(c, sel);
                if (!m) continue;
                const char *enc = method_getTypeEncoding(m);
                if (enc && (strcmp(enc,"c@:")==0 || strcmp(enc,"B@:")==0)) {
                    if (method_getImplementation(m) != s_fakeTrueImp) {
                        method_setImplementation(m, s_fakeTrueImp);
                    }
                }
            }
        } @catch (NSException *e) {
            NSLog(@"[QBLHook] exc: %@", e);
        }
    }
    free(list);
}

__attribute__((constructor))
static void init(void) {
    s_fakeTrueImp = (IMP)fake_TRUE;
    NSLog(@"[QBLHook] v4 loaded");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0*NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ scanAndHook(); NSLog(@"[QBLHook] scan1 done"); });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0*NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ scanAndHook(); NSLog(@"[QBLHook] scan2 done"); });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6.0*NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ scanAndHook(); NSLog(@"[QBLHook] scan3 done"); });
}
