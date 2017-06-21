// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <fb/fbjni.h>
#include <conceal/Buffer.h>
#include <conceal/CryptoConfig.h>
#include <conceal/KeyChain.h>
#include <conceal/Slice.h>
#include "JKeyChain.h"

namespace facebook { namespace conceal { namespace jni {

/**
 * Implements native interface conceal/KeyChain.h based on an object from Java.
 * It holds a global_ref to that object (JKeyChain) so it's not garbage collected.
 * MAYBE this global_ref and JKeyChain could be merged as
 * both fit the same purpose: adapting and translating Java object
 */
class KeyChainFromJava: public KeyChain {
 public:
  KeyChainFromJava(CryptoConfig config, facebook::jni::alias_ref<JKeyChain::javaobject> jKeyChain);

  const Slice getKey();
  Buffer createIv();

 private:
  CryptoConfig config_;
  Buffer key_;
  facebook::jni::global_ref<JKeyChain::javaobject> jKeyChain_;

  void updateMyKey();
};

}}}
