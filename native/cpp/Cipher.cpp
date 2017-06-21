// Copyright 2004-present Facebook. All Rights Reserved.

#include "Cipher.h"

#include <stdexcept>

namespace facebook { namespace conceal {

Cipher::Cipher(CryptoConfig config, KeyChain& keyChain)
  : config_(config), keyChain_(keyChain) {

  // check keyChain matches config
  if (keyChain.getKey().length() != config.keyLength) {
    throw std::invalid_argument("Key chain produces incorrect key length");
  }
  if (keyChain.createIv().length() != config.ivLength) {
    throw std::invalid_argument("Key chain produces incorrect IV length");
  }
}

Encrypt Cipher::createEncrypt(Slice entity) {
  Slice key = keyChain_.getKey();
  Buffer iv = keyChain_.createIv();
  return Encrypt(config_, key, iv, entity);
}

Decrypt Cipher::createDecrypt(Slice entity) {
  Slice key = keyChain_.getKey();
  return Decrypt(config_, key, entity);
}

}}
