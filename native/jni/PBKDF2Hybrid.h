// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <fb/fbjni.h>
#include <conceal/PBKDF2.h>

namespace facebook { namespace conceal { namespace jni {

class PBKDF2Hybrid: public facebook::jni::HybridClass<PBKDF2Hybrid> {

 public:
  constexpr static auto kJavaDescriptor = "Lcom/facebook/cipher/jni/PBKDF2Hybrid;";

  static facebook::jni::local_ref<jhybriddata> initHybrid(facebook::jni::alias_ref<jclass>);

  static void registerNatives();

  void setIterations(jint iterations);
  void setPassword(facebook::jni::alias_ref<jbyteArray> data, jint offset, jint count);
  void setSalt(facebook::jni::alias_ref<jbyteArray> data, jint offset, jint count);
  void setKeyLengthInBytes(jint keyLength);

  facebook::jni::local_ref<jbyteArray> generate();

  facebook::jni::local_ref<jbyteArray> getKey();
  facebook::jni::local_ref<jbyteArray> getSalt();

 private:
   // this is the Conceal++ wrapped object
   PBKDF2 pbkdf2_;

  friend HybridBase;

  PBKDF2Hybrid() {}
};

}}}
