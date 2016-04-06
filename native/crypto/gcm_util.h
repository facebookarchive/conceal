#ifndef HEADER_JAVA_COM_FACEBOOK_CRYPTO_GCM_UTIL_H
#define HEADER_JAVA_COM_FACEBOOK_CRYPTO_GCM_UTIL_H

#include <jni.h>
#include <openssl/evp.h>

typedef struct GCM_JNI_CTX {
  jbyte* key;
  jbyte* iv;
  EVP_CIPHER_CTX* cipherCtx;
} GCM_JNI_CTX;

extern const int GCM_ENCRYPT_MODE;
extern const int GCM_DECRYPT_MODE;

void Init_GCM_CTX_Ptr_Field(JNIEnv* env);

int Init_GCM(JNIEnv* env, jobject obj, jbyteArray key, jbyteArray iv, jint mode);

GCM_JNI_CTX* Create_GCM_JNI_CTX(jbyte* keyBytes, jbyte* ivBytes);

GCM_JNI_CTX* Get_GCM_JNI_CTX(JNIEnv* env, jobject obj);

EVP_CIPHER_CTX* Get_Cipher_CTX(JNIEnv* env, jobject obj);

void Set_GCM_JNI_CTX(JNIEnv* env, jobject obj, GCM_JNI_CTX* ctx);

void Destroy_GCM_JNI_CTX(GCM_JNI_CTX* ctx);

#endif // _JAVA_COM_FACEBOOK_CRYPTO_GCM_UTIL_

