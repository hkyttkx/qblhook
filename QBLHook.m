// AQProbe v2 — 只 hook aqreh.dylib 自己的类
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <UIKit/UIKit.h>

static NSMutableArray *gLog = nil;

static BOOL retYES(id s, SEL c) { return YES; }
static BOOL retNO (id s, SEL c) { return NO; }
static BOOL retYES1(id s, SEL c, id a) { return YES; }
static BOOL retNO1 (id s, SEL c, id a) { return NO; }
static BOOL retYES2(id s, SEL c, id a, id b) { return YES; }

static void L(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (gLog) [gLog addObject:s];
    NSLog(@"[AQProbe] %@", s);
}

// 只认 aqreh 自己的类（按 image 路径）
static BOOL isTargetClass(Class c) {
    const char *img = class_getImageName(c);
    if (!img) return NO;
    if (strstr(img, "aqreh") || strstr(img, "AQREH")) return YES;
    // 备选：按已知类名
    const char *cn = class_getName(c);
    if (cn && (strcmp(cn,"ImGuiDrawView")==0 || strcmp(cn,"PubgLoad")==0 ||
               strcmp(cn,"PubgLoadTrigger")==0 || strcmp(cn,"JHPP")==0 ||
               strcmp(cn,"Logger")==0 || strcmp(cn,"PlistManager")==0)) return YES;
    return NO;
}

static IMP o_derive=NULL,o_decrypt=NULL,o_encrypt=NULL,o_rsa=NULL,o_uuid=NULL,o_key=NULL,o_alert=NULL;

static id my_derive(id self, SEL cmd, id nonce) {
    id k = ((id(*)(id,SEL,id))o_derive)(self, cmd, nonce);
    L(@"deriveAESKey nonce=%@\n -> key=%@", nonce, k);
    return k;
}
static id my_decrypt(id self, SEL cmd, id data, id key) {
    id out = ((id(*)(id,SEL,id,id))o_decrypt)(self, cmd, data, key);
    L(@"DECRYPT key=%@\n in=%@\n out=%@", key,
      [(NSData*)data base64EncodedStringWithOptions:0],
      [out isKindOfClass:[NSData class]] ? [(NSData*)out base64EncodedStringWithOptions:0] : out);
    return out;
}
static id my_encrypt(id self, SEL cmd, id data, id key) {
    id out = ((id(*)(id,SEL,id,id))o_encrypt)(self, cmd, data, key);
    L(@"ENCRYPT key=%@ in=%@", key, data);
    return out;
}
static id my_rsa(id self, SEL cmd, id data) {
    NSString *s=[[NSString alloc] initWithData:(NSData*)data encoding:NSUTF8StringEncoding];
    L(@"RSA-REQ body=%@", s ?: data);
    return ((id(*)(id,SEL,id))o_rsa)(self, cmd, data);
}
static BOOL my_sig(id self, SEL cmd, id sig, id data) {
    NSString *ds=[[NSString alloc] initWithData:(NSData*)data encoding:NSUTF8StringEncoding];
    L(@"VERIFY-SIG sig=%@\n data=%@", sig, ds ?: data);
    return YES;
}
static void my_alert(id self, SEL cmd, id msg) {
    L(@">>> showAlert: %@", msg);
    if (o_alert) ((void(*)(id,SEL,id))o_alert)(self, cmd, msg);
}

static void run(void) {
    gLog = [NSMutableArray array];
    L(@"== AQProbe v2 ==");

    struct { const char *name; IMP imp; } tab[] = {
        {"isProxy",(IMP)retNO}, {"isAllowedAuthURL:",(IMP)retYES1},
        {"verifyResponseSignature:forData:",(IMP)my_sig}, {"isNonceUsed:",(IMP)retNO1},
        {NULL,NULL}
    };
    struct { const char *name; IMP imp; IMP *orig; } rec[] = {
        {"deriveAESKeyFromNonce:",(IMP)my_derive,&o_derive},
        {"decryptData:withKey:",(IMP)my_decrypt,&o_decrypt},
        {"encryptData:withKey:",(IMP)my_encrypt,&o_encrypt},
        {"rsaEncryptData:",(IMP)my_rsa,&o_rsa},
        {"showAlertWithMessage",(IMP)my_alert,&o_alert},
        {NULL,NULL,NULL}
    };

    int n=objc_getClassList(NULL,0);
    Class *list=(Class*)malloc(sizeof(Class)*n);
    objc_getClassList(list,n);
    int hits=0;

    for (int i=0;i<n;i++){
        Class c=list[i];
        if (!isTargetClass(c)) continue;
        hits++;
        const char *img=class_getImageName(c);
        L(@"-- 类 <%s> img=%s", class_getName(c), img?img:"?");
        @try {
            for (int k=0;tab[k].name;k++){
                SEL sel=sel_registerName(tab[k].name);
                Method m=class_getInstanceMethod(c,sel);
                if(!m) continue;
                L(@"   hook %s [%s]",tab[k].name,method_getTypeEncoding(m));
                if(method_getImplementation(m)!=tab[k].imp) method_setImplementation(m,tab[k].imp);
            }
            for (int k=0;rec[k].name;k++){
                SEL sel=sel_registerName(rec[k].name);
                Method m=class_getInstanceMethod(c,sel);
                if(!m) continue;
                L(@"   rec  %s [%s]",rec[k].name,method_getTypeEncoding(m));
                IMP cur=method_getImplementation(m);
                if(cur!=rec[k].imp){ *rec[k].orig=cur; method_setImplementation(m,rec[k].imp); }
            }
        } @catch(NSException *e){}
    }
    free(list);
    L(@"命中 aqreh 类数=%d", hits);

    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *win=nil;
        for (UIWindow *w in [UIApplication sharedApplication].windows) if(w.isKeyWindow) win=w;
        if(!win) win=[UIApplication sharedApplication].windows.firstObject;
        UIViewController *root=win.rootViewController;
        while(root.presentedViewController) root=root.presentedViewController;
        if(!root) return;
        NSString *msg=[gLog componentsJoinedByString:@"\n"];
        if(msg.length>3500) msg=[msg substringToIndex:3500];
        UIAlertController *al=[UIAlertController alertControllerWithTitle:@"AQProbe v2"
                                    message:msg preferredStyle:UIAlertControllerStyleAlert];
        [al addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [root presentViewController:al animated:YES completion:nil];
    });
}

__attribute__((constructor))
static void init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(3.0*NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ run(); });
}
