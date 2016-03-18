#ifndef HEADER_JAVA_COM_FACEBOOK_CRYPTO_UTIL_H
#define HEADER_JAVA_COM_FACEBOOK_CRYPTO_UTIL_H

#include <jni.h>

extern const int CRYPTO_SUCCESS;
extern const int CRYPTO_FAILURE;

extern const int CRYPTO_NO_BYTES_WRITTEN;

jlong Get_JNI_CTX(JNIEnv* env, jobject obj, jfieldID fieldId);
void Set_JNI_CTX(JNIEnv* env, jobject obj, jfieldID fieldId, jlong ctx);

#endif // _JAVA_COM_FACEBOOK_CRYPTO_UTIL_

