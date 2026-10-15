// QBLHook.m v3 — 完整版：枚举验证类 + hook 登录逻辑
// 策略：方法名是明文、类名是哈希 → 按"实现了目标方法名的类"定位

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

// 目标方法（明文已知）
static const char *kLoginMethods[] = {
    "handleLoginLogic",
    "startLoginFlow",
    "sendLogin:",
    "sendLogin:completion:",
    "sendLoginMessage:completion:",
    NULL
};
static const char *kFlagGetters[] = {
    "validKey", "isHackActive", "isValidKey", "activated", "isActivated", NULL
};

static IMP s_origSendLogin = NULL;
static IMP s_origHandleLogin = NULL;

// 让"验证结果"回调直接告诉调用方成功
// sendLogin:completion: 签名 = void (id, SEL, id, void(^)(BOOL))
static void fake_sendLogin_completion(id self, SEL _cmd, id arg, void (^completion)(BOOL)) {
    NSLog(@"[QBLHook] sendLogin:completion: intercepted on <%s>", class_getName(object_getClass(self)));
    if (completion) {
        completion(YES);   // 直接回调成功
    }
}

// handleLoginLogic 签名未知，用 void (id, SEL) 兜底 —— 只打印不替换，避免崩
static void fake_handleLogin(id self, SEL _cmd) {
    NSLog(@"[QBLHook] handleLoginLogic called on <%s>", class_getName(object_getClass(self)));
}

static void scanAndHook(void) {
    int n = objc_getClassList(NULL, 0);
    if (n <= 0) return;
    Class *list = malloc(sizeof(Class) * n);
    if (!list) return;
    objc_getClassList(list, n);

    for (int i = 0; i < n; i++) {
        Class c = list[i];

        // ---- 1. 找实现了登录方法的类，先只报告 ----
        for (int k = 0; kLoginMethods[k]; k++) {
            SEL sel = sel_registerName(kLoginMethods[k]);
            Method m = class_getInstanceMethod(c, sel);
            if (m) {
                NSLog(@"[QBLHook] >>> class <%s> implements -%s  enc=%s",
                      class_getName(c), kLoginMethods[k], method_getTypeEncoding(m));
            }
        }

        // ---- 2. hook sendLogin:completion: ----
        SEL sc = sel_registerName("sendLogin:completion:");
        Method msc = class_getInstanceMethod(c, sc);
        if (msc) {
            const char *enc = method_getTypeEncoding(msc);
            NSLog(@"[QBLHook] sendLogin:completion: enc=%s on <%s>", enc, class_getName(c));
            // 只有签名匹配才替换
            if (enc && strcmp(enc, "v24@0:8@16@?24") == 0) {
                s_origSendLogin = method_getImplementation(msc);
                method_setImplementation(msc, (IMP)fake_sendLogin_completion);
                NSLog(@"[QBLHook] HOOKED sendLogin:completion: on <%s>", class_getName(c));
            }
        }

        // ---- 3. hook 状态 getter（签名精确匹配才替换）----
        for (int k = 0; kFlagGetters[k]; k++) {
            SEL sel = sel_registerName(kFlagGetters[k]);
            Method m = class_getInstanceMethod(c, sel);
            if (!m) continue;
            const char *enc = method_getTypeEncoding(m);
            if (enc && (strcmp(enc, "c@:") == 0 || strcmp(enc, "B@:") == 0)) {
                if (method_getImplementation(m) != (IMP)fake_sendLogin_completion) {
                    method_setImplementation(m, (IMP)imp_implementationWithBlock(^BOOL(id s){ return YES; }));
                }
            }
        }
    }
    free(list);
}

__attribute__((constructor))
static void init(void) {
    NSLog(@"[QBLHook] v3 loaded");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ scanAndHook(); NSLog(@"[QBLHook] scan1 done"); });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ scanAndHook(); NSLog(@"[QBLHook] scan2 done"); });
}
