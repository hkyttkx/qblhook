// CryptoHook MVP1 — 通用 iOS 加解密 Hook
// 技术：dyld interpose（__DATA,__interpose），自包含，不依赖 substrate
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonHMAC.h>
#include <Security/Security.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#define LogPath "/var/mobile/Library/Logs/CryptoHook.log"
static FILE *gFp = NULL;

static void mklog(void){
    if(gFp) return;
    gFp=fopen(LogPath,"a");
    if(!gFp) gFp=fopen("/tmp/CryptoHook.log","a");
}

static NSString *hexdump(const void *p, size_t n){
    if(!p||!n) return @"(null)";
    const uint8_t *b=(const uint8_t*)p;
    size_t lim = n>512?512:n;
    NSMutableString *s=[NSMutableString stringWithCapacity:lim*2];
    for(size_t i=0;i<lim;i++) [s appendFormat:@"%02x",b[i]];
    if(n>lim) [s appendFormat:@"...(共%luB)",(unsigned long)n];
    return s;
}
static NSString *tryText(const void *p, size_t n){
    if(!p||!n||n>4096) return nil;
    NSData *d=[NSData dataWithBytes:p length:n];
    NSString *s=[[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    if(s&&s.length>0) return s;
    return nil;
}
static void LOG(NSString *fmt,...){
    va_list ap; va_start(ap,fmt);
    NSString *s=[[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[CryptoHook] %@",s);
    mklog();
    if(gFp){ fprintf(gFp,"%s\n",s.UTF8String); fflush(gFp); }
}

#define DYLD_INTERPOSE(_rep,_old) \
  __attribute__((used)) static struct { const void* r; const void* o; } \
  _i_##_old __attribute__((section("__DATA,__interpose"))) = { (const void*)_rep, (const void*)_old };

// ================= ① CCCrypt =================
static CCCryptorStatus my_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions opt,
    const void *key, size_t keyLen, const void *iv,
    const void *in, size_t inLen, void *out, size_t outAvail, size_t *moved) {
    LOG(@"=== CCCrypt op=%u alg=%u opt=%u keyLen=%zu inLen=%zu", op,alg,opt,keyLen,inLen);
    LOG(@"  KEY=%@", hexdump(key,keyLen));
    if(iv) LOG(@"  IV =%@", hexdump(iv,16));
    LOG(@"  IN =%@", hexdump(in,inLen));
    NSString *t0=tryText(in,inLen); if(t0) LOG(@"  INTEXT=%@",t0);
    CCCryptorStatus r = CCCrypt(op,alg,opt,key,keyLen,iv,in,inLen,out,outAvail,moved);
    if(out && moved && *moved){
        LOG(@"  OUT=%@", hexdump(out,*moved));
        NSString *t=tryText(out,*moved); if(t) LOG(@"  OUTTEXT=%@",t);
    }
    LOG(@"  rc=%d", (int)r);
    return r;
}
DYLD_INTERPOSE(my_CCCrypt, CCCrypt)

// ================= CCCryptor 流式 =================
static CCCryptorStatus my_CCCryptorCreate(CCOperation op, CCAlgorithm alg, CCOptions opt,
    const void *key, size_t keyLen, const void *iv, CCCryptorRef *ref) {
    LOG(@"=== CCCryptorCreate op=%u alg=%u opt=%u keyLen=%zu",op,alg,opt,keyLen);
    LOG(@"  KEY=%@", hexdump(key,keyLen));
    if(iv) LOG(@"  IV =%@", hexdump(iv,16));
    return CCCryptorCreate(op,alg,opt,key,keyLen,iv,ref);
}
DYLD_INTERPOSE(my_CCCryptorCreate, CCCryptorCreate)

static CCCryptorStatus my_CCCryptorUpdate(CCCryptorRef ref, const void *in, size_t inLen,
    void *out, size_t outAvail, size_t *moved) {
    CCCryptorStatus r = CCCryptorUpdate(ref,in,inLen,out,outAvail,moved);
    LOG(@"=== CCCryptorUpdate inLen=%zu -> moved=%zu",inLen,moved?*moved:0);
    LOG(@"  IN =%@", hexdump(in,inLen));
    if(out&&moved&&*moved) LOG(@"  OUT=%@", hexdump(out,*moved));
    return r;
}
DYLD_INTERPOSE(my_CCCryptorUpdate, CCCryptorUpdate)

static CCCryptorStatus my_CCCryptorFinal(CCCryptorRef ref, void *out, size_t outAvail, size_t *moved) {
    CCCryptorStatus r = CCCryptorFinal(ref,out,outAvail,moved);
    if(out&&moved&&*moved) LOG(@"=== CCCryptorFinal OUT=%@", hexdump(out,*moved));
    return r;
}
DYLD_INTERPOSE(my_CCCryptorFinal, CCCryptorFinal)

// ================= ② HMAC =================
static void my_CCHmac(CCHmacAlgorithm alg, const void *key, size_t keyLen,
                      const void *data, size_t dataLen, void *out) {
    LOG(@"=== CCHmac alg=%u keyLen=%zu dataLen=%zu",alg,keyLen,dataLen);
    LOG(@"  KEY=%@", hexdump(key,keyLen));
    LOG(@"  DATA=%@", hexdump(data,dataLen));
    CCHmac(alg,key,keyLen,data,dataLen,out);
    size_t dlen = alg==kCCHmacAlgSHA256?32:alg==kCCHmacAlgSHA1?20:alg==kCCHmacAlgSHA512?64:16;
    LOG(@"  OUT=%@", hexdump(out,dlen));
}
DYLD_INTERPOSE(my_CCHmac, CCHmac)

// ================= 摘要 =================
static void my_CC_SHA256(const void *data, CC_LONG len, unsigned char *md){
    LOG(@"=== CC_SHA256 len=%u IN=%@",len,hexdump(data,len));
    CC_SHA256(data,len,md);
    LOG(@"  OUT=%@", hexdump(md,32));
}
DYLD_INTERPOSE(my_CC_SHA256, CC_SHA256)

static void my_CC_MD5(const void *data, CC_LONG len, unsigned char *md){
    LOG(@"=== CC_MD5 len=%u IN=%@",len,hexdump(data,len));
    CC_MD5(data,len,md);
    LOG(@"  OUT=%@", hexdump(md,16));
}
DYLD_INTERPOSE(my_CC_MD5, CC_MD5)

// ================= 密钥派生 =================
static int my_CCKeyDerivationPBKDF(CCPBKDFAlgorithm alg, const char *pw, size_t pwLen,
    const uint8_t *salt, size_t saltLen, CCPseudoRandomAlgorithm prf, uint rounds,
    uint8_t *derived, size_t derivedLen) {
    LOG(@"=== PBKDF2 prf=%u rounds=%u saltLen=%zu derivedLen=%zu",prf,rounds,saltLen,derivedLen);
    LOG(@"  SALT=%@", hexdump(salt,saltLen));
    int r = CCKeyDerivationPBKDF(alg,pw,pwLen,salt,saltLen,prf,rounds,derived,derivedLen);
    LOG(@"  KEY=%@", hexdump(derived,derivedLen));
    return r;
}
DYLD_INTERPOSE(my_CCKeyDerivationPBKDF, CCKeyDerivationPBKDF)

// ================= ③ Security 非对称 =================
static CFDataRef my_SecKeyCreateDecryptedData(SecKeyRef key, SecKeyAlgorithm alg,
                                              CFDataRef data, CFErrorRef *err) {
    LOG(@"=== SecKeyDecrypt alg=%@ len=%lu",(__bridge id)alg,(unsigned long)CFDataGetLength(data));
    LOG(@"  IN =%@", hexdump(CFDataGetBytePtr(data),CFDataGetLength(data)));
    CFDataRef out = SecKeyCreateDecryptedData(key,alg,data,err);
    if(out){ LOG(@"  OUT=%@", hexdump(CFDataGetBytePtr(out),CFDataGetLength(out)));
        NSString *t=tryText(CFDataGetBytePtr(out),CFDataGetLength(out)); if(t) LOG(@"  OUTTEXT=%@",t); }
    return out;
}
DYLD_INTERPOSE(my_SecKeyCreateDecryptedData, SecKeyCreateDecryptedData)

static CFDataRef my_SecKeyCreateEncryptedData(SecKeyRef key, SecKeyAlgorithm alg,
                                              CFDataRef data, CFErrorRef *err) {
    LOG(@"=== SecKeyEncrypt alg=%@ len=%lu",(__bridge id)alg,(unsigned long)CFDataGetLength(data));
    LOG(@"  IN =%@", hexdump(CFDataGetBytePtr(data),CFDataGetLength(data)));
    CFDataRef out = SecKeyCreateEncryptedData(key,alg,data,err);
    if(out) LOG(@"  OUT=%@", hexdump(CFDataGetBytePtr(out),CFDataGetLength(out)));
    return out;
}
DYLD_INTERPOSE(my_SecKeyCreateEncryptedData, SecKeyCreateEncryptedData)

// ================= ④ ObjC 自研方法扫描 =================
static const char *kKW[]={"decrypt","encrypt","aes","rsa","hmac","cipher","crypto",
                          "derive","nonce","sign","digest","md5","sha","crypt","key",NULL};

static void scanObjC(void){
    int n=objc_getClassList(NULL,0);
    Class *list=(Class*)malloc(sizeof(Class)*n);
    objc_getClassList(list,n);
    int cnt=0;
    for(int i=0;i<n;i++){
        Class c=list[i];
        const char *img=class_getImageName(c);
        if(!img) continue;
        // 跳过纯系统框架（保留 app + 第三方 dylib + framework）
        if(strstr(img,"/usr/lib/")||strstr(img,"/System/Library/Frameworks/")) continue;
        unsigned mc=0; Method *ms=class_copyMethodList(c,&mc);
        for(unsigned k=0;k<mc;k++){
            const char *sn=sel_getName(method_getName(ms[k]));
            char low[300]; size_t L=strlen(sn); if(L>280)L=280;
            for(size_t j=0;j<L;j++) low[j]=(char)tolower((unsigned char)sn[j]);
            low[L]=0;
            for(int w=0;kKW[w];w++){
                if(strstr(low,kKW[w])){
                    LOG(@"[OBJC] <%s> -%s  enc=%s",class_getName(c),sn,
                        method_getTypeEncoding(ms[k]));
                    cnt++; break;
                }
            }
        }
        free(ms);
    }
    free(list);
    LOG(@"[OBJC] 命中加解密相关方法: %d",cnt);
}

__attribute__((constructor))
static void init(void){
    LOG(@"");
    LOG(@"========== CryptoHook MVP1 loaded (pid=%d) ==========", getpid());
    scanObjC();
    LOG(@"========== scan done ==========");
}
