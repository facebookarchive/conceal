/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <gcm_util.h>
#include <jni.h>
#include <openssl/evp.h>
#include <util.h>

static const int GCM_CIPHER_BLOCK_SIZE_BYTES = 16;

JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeGCMCipher_nativeEncryptFinal(
  JNIEnv* env,
  jobject obj,
  jbyteArray macTag,
  jint tagLen) {

  int bytesWritten = 0;
  EVP_CIPHER_CTX* ctx = Get_Cipher_CTX(env, obj);
  if (!ctx) {
    return CRYPTO_FAILURE;
  }

  jbyte* tagBytes = (*env)->GetByteArrayElements(env, macTag, NULL);
  if (!tagBytes) {
    return CRYPTO_FAILURE;
  }

  int retCode = CRYPTO_SUCCESS;
  if (!retCode || !EVP_EncryptFinal_ex(ctx, tagBytes, &bytesWritten)) {
    retCode = CRYPTO_FAILURE;
  }

  if (!retCode || !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tagLen, tagBytes)) {
    retCode = CRYPTO_FAILURE;
  }

  (*env)->ReleaseByteArrayElements(env, macTag, tagBytes, 0);
  return retCode;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeGCMCipher_nativeDestroy(
  JNIEnv* env,
  jobject obj) {

  GCM_JNI_CTX* ctx = Get_GCM_JNI_CTX(env, obj);
  if (!ctx) {
    return CRYPTO_FAILURE;
  }

  Destroy_GCM_JNI_CTX(ctx);
  Set_GCM_JNI_CTX(env, obj, 0);
  return CRYPTO_SUCCESS;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeGCMCipher_nativeEncryptInit(
  JNIEnv* env,
  jobject obj,
  jbyteArray key,
  jbyteArray iv) {

  if (!Init_GCM(env, obj, key, iv, GCM_ENCRYPT_MODE)) {
    return CRYPTO_FAILURE;
  }

  EVP_CIPHER_CTX* ctx = Get_Cipher_CTX(env, obj);
  if (!ctx) {
    return CRYPTO_FAILURE;
  }

  return CRYPTO_SUCCESS;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeGCMCipher_nativeDecryptInit(
  JNIEnv* env,
  jobject obj,
  jbyteArray key,
  jbyteArray iv) {

  if (!Init_GCM(env, obj, key, iv, GCM_DECRYPT_MODE)) {
    return CRYPTO_FAILURE;
  }

  return CRYPTO_SUCCESS;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeGCMCipher_nativeUpdate(
  JNIEnv* env,
  jobject obj,
  jbyteArray data,
  jint offset,
  jint dataLength,
  jbyteArray output,
  jint outputOffset) {

  int bytesWritten = 0;
  EVP_CIPHER_CTX* ctx = Get_Cipher_CTX(env, obj);
  if (!ctx) {
    return CRYPTO_NO_BYTES_WRITTEN;
  }

  jbyte* outputBytes = (*env)->GetByteArrayElements(env, output, NULL);
  if (!outputBytes) {
    return CRYPTO_NO_BYTES_WRITTEN;
  }

  jbyte* dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
  if (!dataBytes) {
    (*env)->ReleaseByteArrayElements(env, output, outputBytes, 0);
    return CRYPTO_NO_BYTES_WRITTEN;
  }

  if (!EVP_CipherUpdate(ctx, outputBytes + outputOffset, &bytesWritten, dataBytes + offset, dataLength)) {
    bytesWritten = CRYPTO_NO_BYTES_WRITTEN;
  }

  (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, output, outputBytes, 0);

  return bytesWritten;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeGCMCipher_nativeUpdateAad(
  JNIEnv* env,
  jobject obj,
  jbyteArray data,
  jint dataLength) {

  int bytesWritten = 0;
  EVP_CIPHER_CTX* ctx = Get_Cipher_CTX(env, obj);
  if (!ctx) {
    return CRYPTO_NO_BYTES_WRITTEN;
  }

  jbyte* dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
  if (!dataBytes) {
    return CRYPTO_NO_BYTES_WRITTEN;
  }

  if (!EVP_CipherUpdate(ctx, NULL, &bytesWritten, dataBytes, dataLength)) {
    bytesWritten = CRYPTO_NO_BYTES_WRITTEN;
  }

  (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
  return bytesWritten;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeGCMCipher_nativeDecryptFinal(
  JNIEnv* env,
  jobject obj,
  jbyteArray macTag,
  jint tagLength) {

  int bytesWritten = 0;
  char temp[1];

  EVP_CIPHER_CTX* ctx = Get_Cipher_CTX(env, obj);
  if (!ctx) {
    return CRYPTO_FAILURE;
  }

  jbyte* tagBytes = (*env)->GetByteArrayElements(env, macTag, NULL);
  if (!tagBytes) {
    return CRYPTO_FAILURE;
  }

  int retCode = CRYPTO_SUCCESS;
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tagLength, tagBytes)) {
    retCode = CRYPTO_FAILURE;
  }

  if (!retCode || !EVP_DecryptFinal_ex(ctx, temp, &bytesWritten)) {
    retCode = CRYPTO_FAILURE;
  }

  (*env)->ReleaseByteArrayElements(env, macTag, tagBytes, JNI_ABORT);

  return retCode;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeGCMCipher_nativeGetCipherBlockSize(
  JNIEnv* env) {

  return GCM_CIPHER_BLOCK_SIZE_BYTES;
}

// Give the java layer access to C constants.
JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeGCMCipher_nativeFailure(
  JNIEnv* env,
  jobject obj) {

  return CRYPTO_FAILURE;
}
