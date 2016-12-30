//
// Created by 陈长松 on 16/12/30.
//
#include "com_chniccs_security_JniUtil.h"
#include <jni.h>
#include <string.h>
/**
 *这个key就是要用来作为keyStore的密码
 */
const char *KEYSTORE_PW = "chniccs_store...";
/**
 *这个key就是要用来作为keyStore的密码
 */
const char *AES_KEY = "chniccs_aes_key.";
/**
 * 发布的app 签名,只有和本签名一致的app 才会返回 AUTH_KEY
 * 这个RELEASE_SIGN的值是上一步用java代码获取的值
 */
const char *RELEASE_SIGN ="308203373082021fa00302010202042ea650d7300d06092a864886f70d01010b0500304c310a30080603550406130166310a30080603550408130166310b3009060355040713026666310b3009060355040a13026666310b3009060355040b13026666310b3009060355040313026666301e170d3136313232393037333635345a170d3431313232333037333635345a304c310a30080603550406130166310a30080603550408130166310b3009060355040713026666310b3009060355040a13026666310b3009060355040b13026666310b300906035504031302666630820122300d06092a864886f70d01010105000382010f003082010a0282010100b9a24dff6159727a767bfd21f88d7c9879cfb087351a11316115c5c4b77aa54d56e7aa85bccfca85541a3fbb0c28015ff7d3abe9224169c7c318c7f6da4522c1d36ff48baab8281daef1f24c64de4289658d450decdc7b96ad8654dab2ecab8908c5a136f94333529ca80cef529f65083fc84b3af1eddbdfda828d0777c31fafdd44e8c6306313bd5f9893ed014d2c964e2fa1e44757f9e7ffdaf1e082b11c1f51f3f726ccd6b4fc012de3f3a1da7c00ba4734bc71a000fc603b9675895797977a18419ae6d5ad4330e54585ec9d7404768d6c2881c8f117f0d1f1b6950af6b2a930b800f64ab1d71ce51fa3cba57d34d261fe322922d97cabcb7dbb177620630203010001a321301f301d0603551d0e041604142eae2456f8abec9422b8e4c830c11bca793cd8e3300d06092a864886f70d01010b050003820101000144d257bdd2b7f730ee023873a4f9f9b17f8439178ccd12244c494b631fe69dada7ca38b1412b153b6ce8c8b4d53e2af86ac7e3875a6a3a0789c96c6edaeb623ce062bed3a7e681fc42bf253d138c71b7f4cab3f4e0a52088175781001f53628cd0ec31118e696525470bef2ddff4640ae3eaebb1bea4331a8a720cc72ab45fdb6bef69eacb279d0cbded150d73fe7e63ba52393a7e88b373250323a342c50f3695151ee4cfb7854e94ce00aa12e41d5c9b458cc519e307ad05e34fed78c3be2ba4a5a436966ed8ec19368d6b54c681ab889927df69ce28404081a53e3ec29f56f51441eecfed76781ef259e99e714c49f65a596e98034e8da7349538452578";

int getSignHashCode(JNIEnv *env, jobject clazz, jobject contextObject){
    jclass native_class = env->GetObjectClass(contextObject);
    jmethodID pm_id = env->GetMethodID(native_class, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject pm_obj = env->CallObjectMethod(contextObject, pm_id);
    jclass pm_clazz = env->GetObjectClass(pm_obj);
// 得到 getPackageInfo 方法的 ID
    jmethodID package_info_id = env->GetMethodID(pm_clazz, "getPackageInfo","(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    jclass native_classs = env->GetObjectClass(contextObject);
    jmethodID mId = env->GetMethodID(native_classs, "getPackageName", "()Ljava/lang/String;");
    jstring pkg_str = static_cast<jstring>(env->CallObjectMethod(contextObject, mId));
// 获得应用包的信息
    jobject pi_obj = env->CallObjectMethod(pm_obj, package_info_id, pkg_str, 64);
// 获得 PackageInfo 类
    jclass pi_clazz = env->GetObjectClass(pi_obj);
// 获得签名数组属性的 ID
    jfieldID signatures_fieldId = env->GetFieldID(pi_clazz, "signatures", "[Landroid/content/pm/Signature;");
    jobject signatures_obj = env->GetObjectField(pi_obj, signatures_fieldId);
    jobjectArray signaturesArray = (jobjectArray)signatures_obj;
    jsize size = env->GetArrayLength(signaturesArray);
    jobject signature_obj = env->GetObjectArrayElement(signaturesArray, 0);
    jclass signature_clazz = env->GetObjectClass(signature_obj);
    jmethodID string_id = env->GetMethodID(signature_clazz, "toCharsString", "()Ljava/lang/String;");
    jstring str = static_cast<jstring>(env->CallObjectMethod(signature_obj, string_id));
    char *c_msg = (char*)env->GetStringUTFChars(str,0);
    //return str;
    if(strcmp(c_msg,RELEASE_SIGN)==0)//签名一致  返回合法的 api key，否则返回错误
    {
        return 1;
    }else
    {
        return 0;
    }
}
/*
 * Class:     com_chniccs_security_JniUtil
 * Method:    getKeyStorePW
 * Signature: (Ljava/lang/Object;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_chniccs_security_JniUtil_getKeyStorePW
        (JNIEnv *env, jobject clazz, jobject contextObject){
    if(getSignHashCode(env,clazz,contextObject)==1){
        return  (env)->NewStringUTF(KEYSTORE_PW);
    } else{
        return (env)->NewStringUTF("error");
    }
}

/*
 * Class:     com_chniccs_security_JniUtil
 * Method:    getAESkey
 * Signature: (Ljava/lang/Object;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_chniccs_security_JniUtil_getAESkey
        (JNIEnv *env, jobject clazz, jobject contextObject){
    if(getSignHashCode(env,clazz,contextObject)==1){
        return  (env)->NewStringUTF(AES_KEY);
    } else{
        return (env)->NewStringUTF("error");
    }
}

