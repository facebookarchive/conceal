/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <hmac_util.h>
#include <jni.h>
#include <openssl/hmac.h>
#include <util.h>

static const int HMAC_LENGTH = 20;

JNIEXPORT int JNICALL Java_com_facebook_crypto_mac_NativeMac_nativeInit(
  JNIEnv* env,
  jobject obj,
  jbyteArray key,
  jint keyLength) {

  jbyte* keyBytes = (*env)->GetByteArrayElements(env, key, NULL);

  if (keyBytes == NULL) {
    return CRYPTO_FAILURE;
  }

  int retCode = CRYPTO_SUCCESS;
  HMAC_JNI_CTX* ctx = Create_HMAC_JNI_CTX(keyBytes, keyLength);
  if (!ctx) {
    retCode = CRYPTO_FAILURE;
  } else {
    Set_HMAC_JNI_CTX(env, obj, ctx);
  }

  (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
  return retCode;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_mac_NativeMac_nativeDestroy(
  JNIEnv* env,
  jobject obj) {

  HMAC_JNI_CTX* ctx = Get_HMAC_JNI_CTX(env, obj);
  if (!ctx) {
    return CRYPTO_FAILURE;
  }

  Destroy_HMAC_JNI_CTX(ctx);
  Set_HMAC_JNI_CTX(env, obj, 0);
  return CRYPTO_SUCCESS;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_mac_NativeMac_nativeUpdate__B(
  JNIEnv* env,
  jobject obj,
  jbyte data) {

  HMAC_CTX* ctx = Get_HMAC_CTX(env, obj);
  if (!ctx) {
    return CRYPTO_FAILURE;
  }

  if (!HMAC_Update(ctx, (unsigned char*)&data, sizeof(jbyte))) {
    return CRYPTO_FAILURE;
  }
  return CRYPTO_SUCCESS;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_mac_NativeMac_nativeUpdate___3BII(
  JNIEnv* env,
  jobject obj,
  jbyteArray data,
  jint offset,
  jint len) {

  HMAC_CTX* ctx = Get_HMAC_CTX(env, obj);
  if (!ctx) {
    return CRYPTO_FAILURE;
  }

  jbyte* dataArray = (jbyte*) malloc(sizeof(jbyte) * len);
  if (!dataArray) {
    return CRYPTO_FAILURE;
  }

  int retCode = CRYPTO_SUCCESS;
  (*env)->GetByteArrayRegion(env, data, offset, len, dataArray);
  if (!HMAC_Update(ctx, (unsigned char*)dataArray, len)) {
    retCode = CRYPTO_FAILURE;
  }

  free(dataArray);
  return retCode;
}

JNIEXPORT jbyteArray JNICALL Java_com_facebook_crypto_mac_NativeMac_nativeDoFinal(
  JNIEnv* env,
  jobject obj) {

  int len = HMAC_LENGTH;
  char result[len];

  HMAC_CTX* ctx = Get_HMAC_CTX(env, obj);
  jbyteArray resultArray = (*env)->NewByteArray(env, len);
  if (!ctx || !resultArray || !HMAC_Final(ctx, result, &len)) {
    return NULL;
  }

  (*env)->SetByteArrayRegion(env, resultArray, 0, len, result);
  return resultArray;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_mac_NativeMac_nativeGetMacLength(JNIEnv* env) {
  return HMAC_LENGTH;
}

// Give the java layer access to C constants.
JNIEXPORT int JNICALL Java_com_facebook_crypto_mac_NativeMac_nativeFailure(
  JNIEnv* env,
  jobject obj) {

  return CRYPTO_FAILURE;
}