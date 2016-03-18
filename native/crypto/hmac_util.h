#ifndef HEADER_JAVA_COM_FACEBOOK_CRYPTO_HMAC_UTIL_H
#define HEADER_JAVA_COM_FACEBOOK_CRYPTO_HMAC_UTIL_H

#include <jni.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

typedef struct HMAC_JNI_CTX {
  jbyte* key;
  HMAC_CTX* hmacCtx;
} HMAC_JNI_CTX;


void Init_HMAC_CTX_Ptr_Field(JNIEnv* env);

HMAC_JNI_CTX* Create_HMAC_JNI_CTX(jbyte* keyBytes, jint keyLength);

HMAC_JNI_CTX* Get_HMAC_JNI_CTX(JNIEnv* env, jobject obj);

HMAC_CTX* Get_HMAC_CTX(JNIEnv* env, jobject obj);

void Set_HMAC_JNI_CTX(JNIEnv* env, jobject obj, HMAC_JNI_CTX* ctx);

void Destroy_HMAC_JNI_CTX(HMAC_JNI_CTX* ctx);

#endif // _JAVA_COM_FACEBOOK_CRYPTO_HMAC_UTIL_

