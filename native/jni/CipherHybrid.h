// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <fb/fbjni.h>
#include <conceal/Cipher.h>
#include "DecryptHybrid.h"
#include "EncryptHybrid.h"
#include "JKeyChain.h"
#include "KeyChainFromJava.h"
#include <memory>

namespace facebook { namespace conceal { namespace jni {

/**
 * Wrapper to offer a Cipher to Java/JNI.
 * A Java KeyChain is passed to the constructor to use as key source.
 * This CipherHybrid will keep a global_ref to it to avoid GC.
 * In the future a similar CipherHybrid not using a Java KeyChain will be delivered too.
 */
class CipherHybrid: public facebook::jni::HybridClass<CipherHybrid> {

 public:
  constexpr static auto kJavaDescriptor = "Lcom/facebook/cipher/jni/CipherHybrid;";

  // For now Java doesn't pass Config nor KeyChain to native
  // That will come later.
  static facebook::jni::local_ref<jhybriddata> initHybrid(
      facebook::jni::alias_ref<jclass>,
      jbyte configId,
      facebook::jni::alias_ref<JKeyChain::javaobject> jKeyChain);

  static void registerNatives();

  facebook::jni::local_ref<EncryptHybrid::jhybridobject> createEncrypt(
      facebook::jni::alias_ref<jbyteArray> entity,
      jint offset,
      int count);
  facebook::jni::local_ref<DecryptHybrid::jhybridobject> createDecrypt(
      facebook::jni::alias_ref<jbyteArray> entity,
      jint offset,
      int count);

  CipherHybrid(Cipher cipher);

 private:
  std::unique_ptr<KeyChainFromJava> keyChainFromJava_;
  // this is the Conceal++ wrapped object
  Cipher cipher_;

  friend HybridBase;

  CipherHybrid(uint8_t configId, alias_ref<JKeyChain::javaobject> jKeyChain);
  CipherHybrid(CryptoConfig config, alias_ref<JKeyChain::javaobject> jKeyChain);
};

}}}
