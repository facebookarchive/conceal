// Copyright 2004-present Facebook. All Rights Reserved.

#include "CipherHybrid.h"
#include "DecryptHybrid.h"
#include "EncryptHybrid.h"
#include "MacDecoderHybrid.h"
#include "MacEncoderHybrid.h"
#include "PBKDF2Hybrid.h"

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
  return facebook::jni::initialize(vm, [] {
    facebook::conceal::jni::CipherHybrid::registerNatives();
    facebook::conceal::jni::DecryptHybrid::registerNatives();
    facebook::conceal::jni::EncryptHybrid::registerNatives();
    facebook::conceal::jni::MacDecoderHybrid::registerNatives();
    facebook::conceal::jni::MacEncoderHybrid::registerNatives();
    facebook::conceal::jni::PBKDF2Hybrid::registerNatives();
  });
}
