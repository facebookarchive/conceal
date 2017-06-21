// Copyright 2004-present Facebook. All Rights Reserved.

#include "PBKDF2Hybrid.h"
#include "JavaArrays.h"

using facebook::jni::alias_ref;
using facebook::jni::local_ref;

namespace facebook { namespace conceal { namespace jni {

local_ref<PBKDF2Hybrid::jhybriddata> PBKDF2Hybrid::initHybrid(alias_ref<jclass>) {
  return makeCxxInstance();
}

void PBKDF2Hybrid::registerNatives() {
  registerHybrid({
    makeNativeMethod("initHybrid",          PBKDF2Hybrid::initHybrid),
    makeNativeMethod("setIterations",       PBKDF2Hybrid::setIterations),
    makeNativeMethod("setPassword",         PBKDF2Hybrid::setPassword),
    makeNativeMethod("setSalt",             PBKDF2Hybrid::setSalt),
    makeNativeMethod("setKeyLengthInBytes", PBKDF2Hybrid::setKeyLengthInBytes),
    makeNativeMethod("generate",            PBKDF2Hybrid::generate),
    makeNativeMethod("getKey",              PBKDF2Hybrid::getKey),
    makeNativeMethod("getSalt",             PBKDF2Hybrid::getSalt),
  });
}

void PBKDF2Hybrid::setIterations(jint iterations) {
  pbkdf2_.setIterations(iterations);
}

void PBKDF2Hybrid::setPassword(alias_ref<jbyteArray> data, jint offset, jint count) {
  auto pinnedData = data->pin();
  ConstSlice slice(reinterpret_cast<uint8_t*>(&pinnedData[0]), pinnedData.size());
  // Slice API will check the boundaries
  pbkdf2_.setPassword(slice(offset, offset + count));
  pinnedData.abort();
}

void PBKDF2Hybrid::setSalt(alias_ref<jbyteArray> data, jint offset, jint count) {
  auto pinnedData = data->pin();
  ConstSlice slice(reinterpret_cast<uint8_t*>(&pinnedData[0]), pinnedData.size());
  // Slice API will check the boundaries
  pbkdf2_.setSalt(slice(offset, offset + count));
  pinnedData.abort();
}

void PBKDF2Hybrid::setKeyLengthInBytes(jint keyLength) {
  pbkdf2_.setKeyLengthInBytes(keyLength);
}

local_ref<jbyteArray> PBKDF2Hybrid::generate() {
  ConstSlice result = pbkdf2_.generate();
  return slice2JavaArray(result);
}

local_ref<jbyteArray> PBKDF2Hybrid::getKey() {
  return slice2JavaArray(pbkdf2_.getKey());
}

local_ref<jbyteArray> PBKDF2Hybrid::getSalt() {
  return slice2JavaArray(pbkdf2_.getSalt());
}

}}}
