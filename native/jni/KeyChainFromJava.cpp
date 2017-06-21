// Copyright 2004-present Facebook. All Rights Reserved.

#include "KeyChainFromJava.h"

using facebook::jni::alias_ref;
using facebook::jni::local_ref;

namespace facebook { namespace conceal { namespace jni {

KeyChainFromJava::KeyChainFromJava(CryptoConfig config, alias_ref<JKeyChain::javaobject> jKeyChain)
  : config_(config), key_(config.keyLength), jKeyChain_(facebook::jni::make_global(jKeyChain)) {}

const Slice KeyChainFromJava::getKey() {
  updateMyKey();
  return key_;
}

Buffer KeyChainFromJava::createIv() {
  Buffer result(config_.ivLength);
  local_ref<jbyteArray> ref = jKeyChain_->getNewIV();
  auto pinned = ref->pin();
  Slice(reinterpret_cast<uint8_t*>(&pinned[0]), pinned.size()).copyTo(result);
  pinned.abort();
  return result;
}

void KeyChainFromJava::updateMyKey() {
  local_ref<jbyteArray> ref = jKeyChain_->getCipherKey();
  auto pinned = ref->pin();
  Slice(reinterpret_cast<uint8_t*>(&pinned[0]), pinned.size()).copyTo(key_);
  pinned.abort();
}

}}}
