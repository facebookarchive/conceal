// Copyright 2004-present Facebook. All Rights Reserved.

#include "CipherHybrid.h"
#include <conceal/Slice.h>

using facebook::jni::alias_ref;
using facebook::jni::local_ref;

namespace facebook { namespace conceal { namespace jni {

local_ref<CipherHybrid::jhybriddata> CipherHybrid::initHybrid(
    alias_ref<jclass>,
    jbyte configId,
    alias_ref<JKeyChain::javaobject> jKeyChain) {
  return makeCxxInstance(configId, jKeyChain);
}

void CipherHybrid::registerNatives() {
  registerHybrid({
    makeNativeMethod("createDecrypt", CipherHybrid::createDecrypt),
    makeNativeMethod("createEncrypt", CipherHybrid::createEncrypt),
    makeNativeMethod("initHybrid", CipherHybrid::initHybrid),
  });
}

CipherHybrid::CipherHybrid(uint8_t configId, alias_ref<JKeyChain::javaobject> jKeyChain):
    CipherHybrid(CryptoConfig::of(configId), jKeyChain) {}

CipherHybrid::CipherHybrid(CryptoConfig config, alias_ref<JKeyChain::javaobject> jKeyChain)
  : keyChainFromJava_(new KeyChainFromJava(config, jKeyChain)),
    cipher_(config, *keyChainFromJava_) {}

CipherHybrid::CipherHybrid(Cipher cipher)
  : keyChainFromJava_(nullptr),
    cipher_(cipher) {}

local_ref<EncryptHybrid::jhybridobject> CipherHybrid::createEncrypt(alias_ref<jbyteArray> entityArray, jint offset, jint count) {
  auto pinnedEntity = entityArray->pin();
  Slice slice(reinterpret_cast<uint8_t*>(&pinnedEntity[0]), pinnedEntity.size());
  Slice entity = slice(offset, offset + count);
  Encrypt encrypt = cipher_.createEncrypt(entity);
  pinnedEntity.abort();
  return EncryptHybrid::newObjectCxxArgs(std::move(encrypt));
}

local_ref<DecryptHybrid::jhybridobject> CipherHybrid::createDecrypt(alias_ref<jbyteArray> entityArray, jint offset, jint count) {
  auto pinnedEntity = entityArray->pin();
  Slice slice(reinterpret_cast<uint8_t*>(&pinnedEntity[0]), pinnedEntity.size());
  Slice entity = slice(offset, offset + count);
  Decrypt decrypt = cipher_.createDecrypt(entity);
  pinnedEntity.abort();
  return DecryptHybrid::newObjectCxxArgs(std::move(decrypt));
}

}}}
