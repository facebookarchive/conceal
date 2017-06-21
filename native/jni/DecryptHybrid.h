// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <fb/fbjni.h>
#include <conceal/CryptoConfig.h>
#include <conceal/Slice.h>
#include <conceal/Decrypt.h>

using facebook::conceal::CryptoConfig;
using facebook::conceal::Decrypt;
using facebook::conceal::Slice;
using facebook::jni::alias_ref;
using facebook::jni::local_ref;
using facebook::jni::HybridClass;

namespace facebook { namespace conceal { namespace jni {

class DecryptHybrid: public HybridClass<DecryptHybrid> {

 public:
  constexpr static auto kJavaDescriptor = "Lcom/facebook/cipher/jni/DecryptHybrid;";

  static local_ref<jhybriddata> initHybrid(
      alias_ref<jclass>,
      alias_ref<jbyteArray> key,
      alias_ref<jbyteArray> entity);

  static void registerNatives();

  void start(alias_ref<jbyteArray>);
  void read(
      alias_ref<jbyteArray> source,
      jint sourceOffset,
      alias_ref<jbyteArray> target,
      jint targetOffset,
      jint count);
  bool end(alias_ref<jbyteArray>);

 private:
   // this is the Conceal++ wrapped object
   Decrypt decrypt_;

  friend HybridBase;

  DecryptHybrid(CryptoConfig config, Slice key, Slice entity);
  DecryptHybrid(Decrypt&& decrypt);

  inline void readSameBuffer(
      alias_ref<jbyteArray> buffer,
      jint sourceOffset,
      jint targetOffset,
      jint count);
};

}}}
