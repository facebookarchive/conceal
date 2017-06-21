// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <stdint.h>
#include <openssl/evp.h>

namespace facebook { namespace conceal {

/**
 * Represents an encryption configuration.
 * For example 128-bits or 256-bits key.
 */
class CryptoConfig {
 public:
  /**
   * This is the unique identifier for the config.
   * It will be included as a prefix when encrypting.
   */
  const uint8_t id;
  const uint8_t keyLength;
  const uint8_t ivLength;
  const uint8_t tagLength;
  const EVP_CIPHER* cipher;

  static CryptoConfig of(uint8_t id);
  static CryptoConfig CONFIG_128();
  static CryptoConfig CONFIG_256();
  bool operator==(const CryptoConfig& other) const;
 private:
  CryptoConfig(uint8_t id, int keyLength, int ivLength, int tagLength, const EVP_CIPHER* cipher);
};

}}
