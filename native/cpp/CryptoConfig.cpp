// Copyright 2004-present Facebook. All Rights Reserved.

#include "CryptoConfig.h"
#include <stdexcept>

namespace facebook { namespace conceal {

constexpr int KEY_128_ID = 1;
constexpr int KEY_256_ID = 2;

CryptoConfig CryptoConfig::of(uint8_t id) {
  switch (id) {
    case KEY_128_ID: return CryptoConfig::CONFIG_128();
    case KEY_256_ID: return CryptoConfig::CONFIG_256();
    default: throw std::invalid_argument("Invalid CryptoConfig id");
  }
}

CryptoConfig CryptoConfig::CONFIG_128() {
   static CryptoConfig result = CryptoConfig(KEY_128_ID, 16, 12, 16, EVP_aes_128_gcm());
   return result;
}

CryptoConfig CryptoConfig::CONFIG_256() {
   static CryptoConfig result = CryptoConfig(KEY_256_ID, 32, 12, 16, EVP_aes_256_gcm());
   return result;
}

CryptoConfig::CryptoConfig(uint8_t id, int keyLength, int ivLength, int tagLength, const EVP_CIPHER* cipher)
  : id(id), keyLength(keyLength), ivLength(ivLength), tagLength(tagLength), cipher(cipher) {}

bool CryptoConfig::operator==(const CryptoConfig& other) const {
  // id is enough to know it's the same
  return id == other.id;
}

}}
