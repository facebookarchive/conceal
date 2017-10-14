// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <fb/fbjni.h>
#include <conceal/MacConfig.h>
#include <conceal/MacEncoder.h>
#include <conceal/Slice.h>

namespace facebook { namespace conceal { namespace jni {

class MacEncoderHybrid: public facebook::jni::HybridClass<MacEncoderHybrid> {

 public:
  constexpr static auto kJavaDescriptor = "Lcom/facebook/cipher/jni/MacEncoderHybrid;";

  static facebook::jni::local_ref<jhybriddata> initHybrid(
      facebook::jni::alias_ref<jclass>,
      facebook::jni::alias_ref<jbyteArray> key,
      facebook::jni::alias_ref<jbyteArray> entity);

  static void registerNatives();

  facebook::jni::local_ref<jbyteArray> start();
  void write(facebook::jni::alias_ref<jbyteArray> data, jint offset, jint count);
  facebook::jni::local_ref<jbyteArray> end();

 private:
   // this is the Conceal++ wrapped object
   MacEncoder encoder_;

  friend HybridBase;

  MacEncoderHybrid(MacConfig config, Slice key, Slice entity);
};

}}}
