// Copyright 2004-present Facebook. All Rights Reserved.

#include "MacConfig.h"

namespace facebook { namespace conceal {

MacConfig MacConfig::get() {
   static MacConfig result = MacConfig(1, 64, 20, EVP_sha1());
   return result;
}

MacConfig::MacConfig(uint8_t id, int keyLength, int tagLength, const EVP_MD* cipher)
  : id(id), keyLength(keyLength), tagLength(tagLength), cipher(cipher) {}

bool MacConfig::operator==(const MacConfig& other) const {
  // id is enough to know it's the same
  return id == other.id;
}

}}
