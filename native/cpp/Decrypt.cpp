// Copyright 2004-present Facebook. All Rights Reserved.

#include "Decrypt.h"

namespace facebook { namespace conceal {

// format indexes and sizes
constexpr int VERSION_SIZE = 2;
constexpr int FORMAT_BYTE = 0;
constexpr int FORMAT_VALUE = 1; // only format
constexpr int CONFIG_BYTE = 1;

constexpr int EVP_SUCCESS = 1; // Init, Update and Final all return 1 for success

Decrypt::Decrypt(CryptoConfig config, Slice key, Slice entity)
  : WithState(State::INITIAL),
    config_(config),
    buffer_(VERSION_SIZE + config_.ivLength + config_.keyLength),
    version_(buffer_(0, VERSION_SIZE)),
    iv_(buffer_(VERSION_SIZE, VERSION_SIZE + config_.ivLength)),
    key_(buffer_(VERSION_SIZE + config_.ivLength)),
    entity_(entity.length()) {

  assert(key_.length() == config_.keyLength);

  // copy data to own it
  key.copyTo(key_);
  entity.copyTo(entity_);

  ctx_ = EVP_CIPHER_CTX_new();
  check(ctx_, "Decrypt context creation failed");
}

Decrypt::Decrypt(Decrypt&& other)
  : WithState(std::move(other)),
    config_(std::move(other.config_)),
    buffer_(std::move(other.buffer_)),
    version_(std::move(other.version_)),
    iv_(std::move(other.iv_)),
    key_(std::move(other.key_)),
    entity_(std::move(other.entity_)) {
  ctx_ = other.ctx_;
  other.ctx_ = nullptr;
}

Decrypt::~Decrypt() {
  if (ctx_ != nullptr) {
    EVP_CIPHER_CTX_free(ctx_);
  }
}

void Decrypt::start(Slice header) {
  checkState(State::INITIAL, State::PROGRESS, "Decryption already started");
  checkArgument(header.length() == VERSION_SIZE + iv_.length(), "Invalid header");

  Buffer version(VERSION_SIZE);
  header(0, VERSION_SIZE).copyTo(version);
  checkArgument(version[FORMAT_BYTE] == FORMAT_VALUE, "Invalid format");
  checkArgument(version[CONFIG_BYTE] == config_.id, "Invalid CryptoConfig");

  header(VERSION_SIZE).copyTo(iv_);
  const EVP_CIPHER* cipher = config_.cipher;

  int code = EVP_DecryptInit_ex(ctx_, cipher, NULL, NULL, NULL);
  check(code == EVP_SUCCESS, "Decryption initialization creation failed (cipher)");
  code = EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_IVLEN, config_.ivLength, NULL);
  check(code == EVP_SUCCESS, "Decryption initialization failed (IV length)");
  code = EVP_DecryptInit_ex(ctx_, NULL, NULL, key_.offset(0), iv_.offset(0));
  check(code == EVP_SUCCESS, "Encryption initialization failed");

  updateAad(version);
  updateAad(entity_);
}

void Decrypt::read(Slice src, Slice target) {
  checkState(State::PROGRESS, State::PROGRESS, "Decryption not in progress");
  checkArgument(src.length() <= target.length(), "Target slice is too short");

  int bytesWritten;
  int code = EVP_CipherUpdate(ctx_, target.offset(0), &bytesWritten, src.offset(0), src.length());
  check(code == EVP_SUCCESS, "Chunk decryption failed");
}

int Decrypt::updateAad(Slice slice) {
  int bytesWritten;
  int code = EVP_CipherUpdate(ctx_, NULL, &bytesWritten, slice.offset(0), slice.length());
  check(code == EVP_SUCCESS, "Aad update failed");
  return bytesWritten;
}

bool Decrypt::end(Slice tail) {
  checkState(State::PROGRESS, State::ENDED, "Decryption not in progress");
  checkArgument(tail.length() == config_.tagLength, "Invalid tail");

  unsigned char temp;
  int bytesWritten;
  int code = EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_TAG, tail.length(), tail.offset(0));
  check(code == EVP_SUCCESS, "Decryption tag check failed");
  return (EVP_DecryptFinal_ex(ctx_, &temp, &bytesWritten) == EVP_SUCCESS);
}

}}
