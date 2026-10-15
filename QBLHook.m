// AQProbe v4 — 放行校验 + 吞掉失败提示 + 主动拉起 ImGui 悬浮窗
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <UIKit/UIKit.h>

static NSMutableArray *gLog = nil;

static void L(NSString *fmt,...){
    va_list ap; va_start(ap,fmt);
    NSString *s=[[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if(gLog) [gLog addObject:s];
    NSLog(@"[AQProbe] %@", s);
}

static BOOL retYES(id s,SEL c){return YES;}
static BOOL retNO (id s,SEL c){return NO;}
static BOOL retYES1(id s,SEL c,id a){return YES;}
static BOOL retNO1 (id s,SEL c,id a){return NO;}

static BOOL ownMethod(Class c, SEL sel){
    unsigned n=0; Method *ms=class_copyMethodList(c,&n);
    BOOL f=NO;
    for(unsigned i=0;i<n;i++) if(method_getName(ms[i])==sel){f=YES;break;}
    free(ms); return f;
}
static BOOL isAqrehClass(Class c){
    const char *img=class_getImageName(c);
    return img && (strstr(img,"AQREH")||strstr(img,"aqreh"));
}

// 吞掉失败提示（不调用原实现）
static void my_alert(id self,SEL cmd,id msg){
    L(@"showAlert(吞掉): %@", msg);
}

static IMP o_decrypt=NULL,o_rsa=NULL,o_verify=NULL;
static id my_decrypt(id self,SEL cmd,id data,id key){
    id out=((id(*)(id,SEL,id,id))o_decrypt)(self,cmd,data,key);
    NSString *p = [out isKindOfClass:[NSData class]]
        ? [[NSString alloc] initWithData:(NSData*)out encoding:NSUTF8StringEncoding] : nil;
    L(@"DECRYPT key=%@\n OUT=%@" , key, p ?: out);
    return out;
}
static id my_rsa(id self,SEL cmd,id data){
    NSString *p=[[NSString alloc] initWithData:(NSData*)data encoding:NSUTF8StringEncoding];
    L(@"RSA-REQ=%@", p ?: @"(binary)");
    return ((id(*)(id,SEL,id))o_rsa)(self,cmd,data);
}
static BOOL my_sig(id self,SEL cmd,id sig,id data){ return YES; }

// 主动拉起悬浮窗
static void kickstart(void){
    NSArray *cls=@[@"ImGuiLoad",@"PubgLoad",@"PubgLoadTrigger"];
    for(NSString *cn in cls){
        Class c=NSClassFromString(cn);
        if(!c){ L(@"类不存在: %@",cn); continue; }
        L(@"尝试拉起 %@",cn);
        // 类方法 load
        if([c respondsToSelector:NSSelectorFromString(@"load")]){
            @try{ ((void(*)(id,SEL))objc_msgSend)((id)c,NSSelectorFromString(@"load")); L(@"  +load ok"); }
            @catch(NSException *e){ L(@"  +load 异常: %@",e); }
        }
        // 实例方法 load
        @try{
            id inst=((id(*)(id,SEL))objc_msgSend)((id)c,sel_registerName("alloc"));
            inst=((id(*)(id,SEL))objc_msgSend)(inst,sel_registerName("init"));
            if(inst && [inst respondsToSelector:NSSelectorFromString(@"load")]){
                ((void(*)(id,SEL))objc_msgSend)(inst,NSSelectorFromString(@"load"));
                L(@"  -load ok");
            }
        } @catch(NSException *e){ L(@"  -load 异常: %@",e); }
    }
    // ImGuiDrawView 直接加到 window
    Class dv=NSClassFromString(@"ImGuiDrawView");
    if(dv){
        L(@"ImGuiDrawView 存在，尝试挂载");
        UIWindow *win=nil;
        for(UIWindow *w in [UIApplication sharedApplication].windows) if(w.isKeyWindow) win=w;
        if(!win) win=[UIApplication sharedApplication].windows.firstObject;
        SEL s=sel_registerName("initWithFrame:togglePtr:iconType:");
        if([dv instancesRespondToSelector:s]){
            @try{
                CGRect f=win.bounds;
                id v=((id(*)(id,SEL,CGRect,void*,id))objc_msgSend)((id)dv,s,f,NULL,@"hack");
                if(v){ [win addSubview:v]; L(@"  已加入 window"); }
            } @catch(NSException *e){ L(@"  挂载异常: %@",e); }
        }
    }
}

static void showLog(void){
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *win=nil;
        for(UIWindow *w in [UIApplication sharedApplication].windows) if(w.isKeyWindow) win=w;
        if(!win) win=[UIApplication sharedApplication].windows.firstObject;
        UIViewController *root=win.rootViewController;
        while(root.presentedViewController) root=root.presentedViewController;
        if(!root) return;
        NSString *msg=[gLog componentsJoinedByString:@"\n"];
        if(msg.length>3400) msg=[msg substringFromIndex:msg.length-3400];
        UIAlertController *al=[UIAlertController alertControllerWithTitle:@"AQProbe v4"
                                    message:msg preferredStyle:UIAlertControllerStyleAlert];
        [al addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [root presentViewController:al animated:YES completion:nil];
    });
}

static void run(void){
    gLog=[NSMutableArray array];
    L(@"== AQProbe v4 ==");

    struct { const char*n; IMP i; } tab[]={
        {"verifyResponseSignature:forData:",(IMP)my_sig},
        {"isProxy",(IMP)retNO},
        {"isAllowedAuthURL:",(IMP)retYES1},
        {"isNonceUsed:",(IMP)retNO1},
        {NULL,NULL}
    };
    struct { const char*n; IMP i; IMP*o; } rec[]={
        {"decryptData:withKey:",(IMP)my_decrypt,&o_decrypt},
        {"rsaEncryptData:",(IMP)my_rsa,&o_rsa},
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
                if(method_getImplementation(m)!=tab[k].i){ method_setImplementation(m,tab[k].i); L(@"[%s] hook %s",class_getName(c),tab[k].n); }
            }
            for(int k=0;rec[k].n;k++){
                SEL sel=sel_registerName(rec[k].n);
                if(!ownMethod(c,sel)) continue;
                Method m=class_getInstanceMethod(c,sel);
                IMP cur=method_getImplementation(m);
                if(cur!=rec[k].i){ *rec[k].o=cur; method_setImplementation(m,rec[k].i); L(@"[%s] rec %s",class_getName(c),rec[k].n); }
            }
            // 吞提示：任何类上定义都替换
            SEL sa=sel_registerName("showAlertWithMessage");
            if(ownMethod(c,sa)){
                Method m=class_getInstanceMethod(c,sa);
                if(method_getImplementation(m)!=(IMP)my_alert){ method_setImplementation(m,(IMP)my_alert); L(@"[%s] 吞掉 showAlertWithMessage",class_getName(c)); }
            }
        } @catch(NSException *e){}
    }
    free(list);
    L(@"aqreh 类=%d",hits);

    // 3 秒后主动拉起悬浮窗
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(3.0*NSEC_PER_SEC)),
                   dispatch_get_main_queue(),^{
        kickstart();
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1.5*NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ showLog(); });
    });
}

__attribute__((constructor))
static void init(void){
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(3.0*NSEC_PER_SEC)),
                   dispatch_get_main_queue(),^{ run(); });
}
