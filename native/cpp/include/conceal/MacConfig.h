// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <cstdint>
#include <openssl/evp.h>

namespace facebook { namespace conceal {

/**
 * Represents an mac configuration.
 */
class MacConfig {
 public:
  /**
   * This is the unique identifier for the config.
   * It will be included as a prefix when encoding.
   */
  const uint8_t id;
  const uint8_t keyLength;
  const uint8_t tagLength;
  const EVP_MD* cipher;

  static MacConfig get();
  bool operator==(const MacConfig& other) const;
 private:
  MacConfig(uint8_t id, int keyLength, int tagLength, const EVP_MD* cipher);
};

}}
