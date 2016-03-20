/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <jni.h>
#include <openssl/evp.h>

JNIEXPORT jint JNICALL Java_com_facebook_crypto_keygen_PasswordBasedKeyDerivation_nativePbkdf2(
    JNIEnv* env,
    jobject obj,
    jstring jPassword,
    jbyteArray jSalt,
    jint iterations,
    jbyteArray jKey) {

  int result = 0; // return error unless we get to process the key successfully
  // the chars from password are encoded in UTF-8 which has a more even byte distribution than UTF16
  jsize passlen = (*env)->GetStringUTFLength(env, jPassword);
  const char * pass = (*env)->GetStringUTFChars(env, jPassword, NULL);

  if (pass != NULL) {
    jsize saltlen = (*env)->GetArrayLength(env, jSalt);
    jbyte * salt = (*env)->GetByteArrayElements(env, jSalt, NULL);

    if (salt != NULL) {
      jsize keylen = (*env)->GetArrayLength(env, jKey);
      jbyte * key = (*env)->GetByteArrayElements(env, jKey, NULL);

      if (key != NULL) {
        result = PKCS5_PBKDF2_HMAC(
            pass,
            passlen,
            (const unsigned char*) salt,
            saltlen,
            iterations,
            EVP_sha256(),
            keylen,
            (unsigned char *) key);

        (*env)->ReleaseByteArrayElements(env, jKey, key, 0);
      }
      (*env)->ReleaseByteArrayElements(env, jSalt, salt, JNI_ABORT);
    }
    (*env)->ReleaseStringUTFChars(env, jPassword, pass);
  }
  return result;
}
