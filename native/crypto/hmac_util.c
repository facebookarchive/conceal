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
#include <hmac_util.h>
#include <util.h>

#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"

static const char* JAVA_HMAC_CLASS = "com/facebook/crypto/mac/NativeMac";

// Cache field id.
static jfieldID fieldId = NULL;

void Init_HMAC_CTX_Ptr_Field(JNIEnv* env) {
  if (!fieldId) {
    jclass hmacClass = (*env)->FindClass(env, JAVA_HMAC_CLASS);
    fieldId = (*env)->GetFieldID(env, hmacClass, "mCtxPtr", "J");
  }
}

HMAC_JNI_CTX* Create_HMAC_JNI_CTX(jbyte* keyBytes, jint keyLength) {
  HMAC_JNI_CTX* ctx = (HMAC_JNI_CTX*) malloc(sizeof(HMAC_JNI_CTX));
  if (!ctx) {
    return NULL;
  }

  ctx->key = (jbyte*) malloc(sizeof(jbyte) * keyLength);
  if (!ctx->key) {
    free(ctx);
    return NULL;
  }

  ctx->hmacCtx = (HMAC_CTX*) malloc(sizeof(HMAC_CTX));
  if (!ctx->hmacCtx) {
    free(ctx->key);
    free(ctx);
    return NULL;
  }

  memcpy(ctx->key, keyBytes, keyLength);

  HMAC_CTX_init(ctx->hmacCtx);
  if (!HMAC_Init_ex(ctx->hmacCtx, ctx->key, keyLength, EVP_sha1(), NULL)) {
    free(ctx->hmacCtx);
    free(ctx->key);
    free(ctx);
    return NULL;
  }

  return ctx;
}

HMAC_JNI_CTX* Get_HMAC_JNI_CTX(JNIEnv* env, jobject obj) {
  return (HMAC_JNI_CTX*) Get_JNI_CTX(env, obj, fieldId);
}

HMAC_CTX* Get_HMAC_CTX(JNIEnv* env, jobject obj) {
  HMAC_JNI_CTX* ctx = Get_HMAC_JNI_CTX(env, obj);
  if (!ctx) {
    return NULL;
  }

  return (HMAC_CTX*) (ctx->hmacCtx);
}

void Set_HMAC_JNI_CTX(JNIEnv* env, jobject obj, HMAC_JNI_CTX* ctx) {
  Set_JNI_CTX(env, obj, fieldId, (jlong) ctx);
}

void Destroy_HMAC_JNI_CTX(HMAC_JNI_CTX* ctx) {
  HMAC_CTX_cleanup(ctx->hmacCtx);
  free(ctx->hmacCtx);
  free(ctx->key);
  free(ctx);
}

