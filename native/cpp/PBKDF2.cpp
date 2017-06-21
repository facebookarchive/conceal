// Copyright 2004-present Facebook. All Rights Reserved.

#include "PBKDF2.h"

namespace facebook { namespace conceal {

constexpr int MINIMUM_SALT_LENGTH = 4;
// there will be a default salt length when it's randomly generated here in C++ (value 16)

constexpr int MINIMUM_ITERATIONS = 1;
constexpr int DEFAULT_ITERATIONS = 4096;

constexpr int MINIMUM_KEY_LENGTH = 8;
constexpr int DEFAULT_KEY_LENGTH = 16;

/**
 * The code returned when OpenSSL generates the key successfully. No constant defined in OpenSSL.
 */
constexpr int RESULT_SUCCESS = 1;

PBKDF2::PBKDF2() {
  iterations_ = DEFAULT_ITERATIONS;
  password_ = nullptr;
  salt_ = nullptr;
  keyLengthInBytes_ = DEFAULT_KEY_LENGTH;
  generatedKey_ = nullptr;
}

void PBKDF2::setIterations(int iterations) {
  if (iterations < MINIMUM_ITERATIONS) {
    throw std::invalid_argument("Invalid number of iterations");
  }
  iterations_ = iterations;
}

void PBKDF2::setPassword(ConstSlice password) {
  password_ = std::make_unique<Buffer>(password.length());
  password.copyTo(*password_);
}
  /**
   * Currently you need to set the salt.
   * Later it will be generated randomly if null.
   */
void PBKDF2::setSalt(ConstSlice salt) {
  if (salt.length() < MINIMUM_SALT_LENGTH) {
    throw std::invalid_argument("Invalid salt length");
  }
  salt_ = std::make_unique<Buffer>(salt.length());
  salt.copyTo(*salt_);
}

void PBKDF2::setKeyLengthInBytes(int keyLength) {
  if (keyLength < MINIMUM_KEY_LENGTH) {
    throw std::invalid_argument("Invalid key length");
  }
  keyLengthInBytes_ = keyLength;
}

ConstSlice PBKDF2::generate() {
  if (password_ == nullptr) {
    throw std::runtime_error("Password cannot be nullptr");
  }
  if (salt_ == nullptr) {
    throw std::runtime_error("Salt cannot be nullptr (random generation not available yet in C++)");
  }
  generatedKey_ = std::make_unique<Buffer>(keyLengthInBytes_);
  int result = PKCS5_PBKDF2_HMAC(
      reinterpret_cast<const char*>(password_->offset(0)),
      password_->length(),
      reinterpret_cast<const unsigned char*>(salt_->offset(0)),
      salt_->length(),
      iterations_,
      EVP_sha256(),
      keyLengthInBytes_,
      reinterpret_cast<unsigned char*>(generatedKey_->offset(0)));

  if (result != RESULT_SUCCESS) {
    throw std::runtime_error("OpenSSL error generating key");
  }
  return *generatedKey_;
}

  // subsequent getters
ConstSlice PBKDF2::getSalt() {
  return *salt_;
}

ConstSlice PBKDF2::getKey() {
  return *generatedKey_;
}

}}
