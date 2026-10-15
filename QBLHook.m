// QBLDump.m — 运行时枚举，找出验证相关的方法名
// 通过 NSLog 输出到 syslog

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

static void dumpClass(Class c) {
    NSString *cname = [NSString stringWithUTF8String:class_getName(c)];
    unsigned int mc = 0;
    Method *methods = class_copyMethodList(c, &mc);
    for (unsigned int i = 0; i < mc; i++) {
        NSString *sel = NSStringFromSelector(method_getName(methods[i]));
        NSString *low = [sel lowercaseString];
        if ([low containsString:@"key"] || [low containsString:@"login"] ||
            [low containsString:@"auth"] || [low containsString:@"valid"] ||
            [low containsString:@"activ"] || [low containsString:@"verif"] ||
            [low containsString:@"check"] || [low containsString:@"buy"] ||
            [low containsString:@"premium"] || [low containsString:@"vip"]) {
            NSLog(@"[QBLDump] %@ -> -%@ (enc=%s)", cname, sel,
                  method_getTypeEncoding(methods[i]));
        }
    }
    free(methods);

    // 也 dump 属性
    unsigned int pc = 0;
    objc_property_t *props = class_copyPropertyList(c, &pc);
    for (unsigned int i = 0; i < pc; i++) {
        NSString *pname = [NSString stringWithUTF8String:property_getName(props[i])];
        NSString *low = [pname lowercaseString];
        if ([low containsString:@"key"] || [low containsString:@"valid"] ||
            [low containsString:@"activ"] || [low containsString:@"auth"]) {
            NSLog(@"[QBLDump] %@ PROP -> %@", cname, pname);
        }
    }
    free(props);
}

static void dumpAll(void) {
    int n = objc_getClassList(NULL, 0);
    Class *list = malloc(sizeof(Class) * n);
    objc_getClassList(list, n);
    NSLog(@"[QBLDump] total classes: %d", n);

    for (int i = 0; i < n; i++) {
        @try { dumpClass(list[i]); } @catch (NSException *e) {}
    }
    free(list);
    NSLog(@"[QBLDump] dump complete");
}

__attribute__((constructor))
static void init(void) {
    NSLog(@"[QBLDump] loaded");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ dumpAll(); });
}
