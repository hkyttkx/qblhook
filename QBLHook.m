// AQProbe v3 — 精确 hook（只本类方法）+ 验证时刻弹窗
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <UIKit/UIKit.h>

static NSMutableArray *gLog = nil;
static BOOL gShown = NO;

static void showNow(void);

static BOOL retYES(id s, SEL c){return YES;}
static BOOL retNO (id s, SEL c){return NO;}
static BOOL retYES1(id s, SEL c, id a){return YES;}
static BOOL retNO1 (id s, SEL c, id a){return NO;}

static void L(NSString *fmt,...){
    va_list ap; va_start(ap,fmt);
    NSString *s=[[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if(gLog) [gLog addObject:s];
    NSLog(@"[AQProbe] %@", s);
}

static BOOL ownMethod(Class c, SEL sel){
    unsigned n=0; Method *ms=class_copyMethodList(c,&n);
    BOOL f=NO;
    for(unsigned i=0;i<n;i++) if(method_getName(ms[i])==sel){ f=YES; break; }
    free(ms); return f;
}

static BOOL isAqrehClass(Class c){
    const char *img=class_getImageName(c);
    if(!img) return NO;
    return strstr(img,"AQREH")||strstr(img,"aqreh");
}

static IMP o_derive=NULL,o_decrypt=NULL,o_encrypt=NULL,o_rsa=NULL,o_alert=NULL;

static id my_derive(id self,SEL cmd,id nonce){
    id k=((id(*)(id,SEL,id))o_derive)(self,cmd,nonce);
    L(@"deriveAESKey nonce=%@ -> key=%@",nonce,k); return k;
}
static id my_decrypt(id self,SEL cmd,id data,id key){
    id out=((id(*)(id,SEL,id,id))o_decrypt)(self,cmd,data,key);
    L(@"DECRYPT key=%@",key);
    L(@"  IN =%@",[(NSData*)data base64EncodedStringWithOptions:0]);
    L(@"  OUT=%@",[out isKindOfClass:[NSData class]]?[(NSData*)out base64EncodedStringWithOptions:0]:out);
    return out;
}
static id my_encrypt(id self,SEL cmd,id data,id key){
    id out=((id(*)(id,SEL,id,id))o_encrypt)(self,cmd,data,key);
    L(@"ENCRYPT key=%@ IN=%@",key,data); return out;
}
static id my_rsa(id self,SEL cmd,id data){
    NSString *s=[[NSString alloc] initWithData:(NSData*)data encoding:NSUTF8StringEncoding];
    L(@"RSA-REQ body=%@", s ?: data);
    return ((id(*)(id,SEL,id))o_rsa)(self,cmd,data);
}
static BOOL my_sig(id self,SEL cmd,id sig,id data){
    NSString *ds=[[NSString alloc] initWithData:(NSData*)data encoding:NSUTF8StringEncoding];
    L(@"VERIFY-SIG sig=%@ data=%@",sig,ds?:data);
    return YES;
}
static void my_alert(id self,SEL cmd,id msg){
    L(@">>> showAlert: %@",msg);
    if(o_alert) ((void(*)(id,SEL,id))o_alert)(self,cmd,msg);
    if(!gShown){ gShown=YES; showNow(); }
}

static void showNow(void){
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *win=nil;
        for(UIWindow *w in [UIApplication sharedApplication].windows) if(w.isKeyWindow) win=w;
        if(!win) win=[UIApplication sharedApplication].windows.firstObject;
        UIViewController *root=win.rootViewController;
        while(root.presentedViewController) root=root.presentedViewController;
        if(!root) return;
        NSMutableArray *lines=[NSMutableArray array];
        for(NSString *s in gLog) if(![s hasPrefix:@"   hook isProxy"]) [lines addObject:s];
        NSString *msg=[lines componentsJoinedByString:@"\n"];
        if(msg.length>3600) msg=[msg substringFromIndex:msg.length-3600];
        UIAlertController *al=[UIAlertController alertControllerWithTitle:@"AQProbe v3"
                                    message:msg preferredStyle:UIAlertControllerStyleAlert];
        [al addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [root presentViewController:al animated:YES completion:nil];
    });
}

static void run(void){
    gLog=[NSMutableArray array];
    L(@"== AQProbe v3 ==");

    struct { const char*n; IMP i; } tab[]={
        {"verifyResponseSignature:forData:",(IMP)my_sig},
        {"isProxy",(IMP)retNO},
        {"isAllowedAuthURL:",(IMP)retYES1},
        {"isNonceUsed:",(IMP)retNO1},
        {NULL,NULL}
    };
    struct { const char*n; IMP i; IMP*o; } rec[]={
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
    for(int i=0;i<n;i++){
        Class c=list[i];
        if(!isAqrehClass(c)) continue;
        hits++;
        @try{
            for(int k=0;tab[k].n;k++){
                SEL sel=sel_registerName(tab[k].n);
                if(!ownMethod(c,sel)) continue;
                Method m=class_getInstanceMethod(c,sel);
                L(@"[%s] hook %s [%s]",class_getName(c),tab[k].n,method_getTypeEncoding(m));
                if(method_getImplementation(m)!=tab[k].i) method_setImplementation(m,tab[k].i);
            }
            for(int k=0;rec[k].n;k++){
                SEL sel=sel_registerName(rec[k].n);
                if(!ownMethod(c,sel)) continue;
                Method m=class_getInstanceMethod(c,sel);
                L(@"[%s] rec %s [%s]",class_getName(c),rec[k].n,method_getTypeEncoding(m));
                IMP cur=method_getImplementation(m);
                if(cur!=rec[k].i){ *rec[k].o=cur; method_setImplementation(m,rec[k].i); }
            }
        } @catch(NSException *e){}
    }
    free(list);
    L(@"aqreh 类数=%d",hits);
    showNow();
}

__attribute__((constructor))
static void init(void){
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(3.0*NSEC_PER_SEC)),
                   dispatch_get_main_queue(),^{ run(); });
}
