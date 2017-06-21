// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <fb/fbjni.h>
#include <conceal/CryptoConfig.h>
#include <conceal/Slice.h>
#include <conceal/Encrypt.h>

using facebook::conceal::CryptoConfig;
using facebook::conceal::Encrypt;
using facebook::conceal::Slice;
using facebook::jni::alias_ref;
using facebook::jni::local_ref;
using facebook::jni::HybridClass;

namespace facebook { namespace conceal { namespace jni {

class EncryptHybrid: public HybridClass<EncryptHybrid> {

 public:
  constexpr static auto kJavaDescriptor = "Lcom/facebook/cipher/jni/EncryptHybrid;";

  static local_ref<jhybriddata> initHybrid(
      alias_ref<jclass>,
      alias_ref<jbyteArray> key,
      alias_ref<jbyteArray> iv,
      alias_ref<jbyteArray> entity);

  static void registerNatives();

  local_ref<jbyteArray> start();
  void write(
      alias_ref<jbyteArray> src,
      jint srcOffset,
      alias_ref<jbyteArray> target,
      jint targetOffset,
      jint count);
  local_ref<jbyteArray> end();

 private:
   // this is the Conceal++ wrapped object
   Encrypt encrypt_;

  friend HybridBase;

  EncryptHybrid(CryptoConfig config, Slice key, Slice iv, Slice entity);
  EncryptHybrid(Encrypt&& encrypt);

  inline void writeSameBuffer(
      alias_ref<jbyteArray> buffer,
      jint srcOffset,
      jint targetOffset,
      jint count);
};

}}}
