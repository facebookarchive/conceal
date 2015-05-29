/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <util.h>

const int CRYPTO_SUCCESS = 1;
const int CRYPTO_FAILURE = 0;

const int CRYPTO_NO_BYTES_WRITTEN = -1;

// Give the java layer access to C constants.
JNIEXPORT int JNICALL Java_com_facebook_crypto_util_NativeUtils_successJni(
  JNIEnv* env,
  jobject obj) {

  return CRYPTO_SUCCESS;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_util_NativeUtils_failureJni(
  JNIEnv* env,
  jobject obj) {

  return CRYPTO_FAILURE;
}

jlong Get_JNI_CTX(JNIEnv* env, jobject obj, jfieldID fieldId) {
  jlong ctx = (*env)->GetLongField(env, obj, fieldId);
  return ctx;
}

void Set_JNI_CTX(JNIEnv* env, jobject obj, jfieldID fieldId, jlong ctx) {
  (*env)->SetLongField(env, obj, fieldId, (jlong) ctx);
}
