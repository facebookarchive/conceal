#ifndef _JAVA_COM_FACEBOOK_CRYPTO_UTIL_
#define _JAVA_COM_FACEBOOK_CRYPTO_UTIL_

#include <jni.h>

extern const int CRYPTO_SUCCESS;
extern const int CRYPTO_FAILURE;

extern const int CRYPTO_NO_BYTES_WRITTEN;

jint Get_JNI_CTX(JNIEnv* env, jobject obj, jfieldID fieldId);

void Set_JNI_CTX(JNIEnv* env, jobject obj, jfieldID fieldId, jint ctx);

#endif // _JAVA_COM_FACEBOOK_CRYPTO_UTIL_

