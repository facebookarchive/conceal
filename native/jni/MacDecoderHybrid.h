// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <fb/fbjni.h>
#include <conceal/MacConfig.h>
#include <conceal/MacDecoder.h>
#include <conceal/Slice.h>

using facebook::conceal::MacConfig;
using facebook::conceal::MacDecoder;
using facebook::conceal::Slice;
using facebook::jni::alias_ref;
using facebook::jni::local_ref;
using facebook::jni::HybridClass;

namespace facebook { namespace conceal { namespace jni {

class MacDecoderHybrid: public HybridClass<MacDecoderHybrid> {

 public:
  constexpr static auto kJavaDescriptor = "Lcom/facebook/cipher/jni/MacDecoderHybrid;";

  static local_ref<jhybriddata> initHybrid(
      alias_ref<jclass>,
      alias_ref<jbyteArray> key,
      alias_ref<jbyteArray> entity);

  static void registerNatives();

  void start(alias_ref<jbyteArray> header);
  void read(alias_ref<jbyteArray> data, jint offset, jint count);
  bool end(alias_ref<jbyteArray> tail);

 private:
   // this is the Conceal++ wrapped object
   MacDecoder decoder_;

  friend HybridBase;

  MacDecoderHybrid(MacConfig config, Slice key, Slice entity);
};

}}}
