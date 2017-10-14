// Copyright 2004-present Facebook. All Rights Reserved.

#include "MacEncoder.h"
#include "CryptoException.h"

#include <stdexcept>

namespace facebook { namespace conceal {

// format indexes and sizes
constexpr int VERSION_SIZE = 2;
constexpr int FORMAT_BYTE = 0;
constexpr int FORMAT_VALUE = 1; // only format
constexpr int CONFIG_BYTE = 1;

constexpr int EVP_SUCCESS = 1; // Init, Update and Final all return 1 for success

MacEncoder::MacEncoder(MacConfig config, Slice key, Slice entity):
    WithState(State::INITIAL),
    config_(config),
    buffer_(VERSION_SIZE + config_.keyLength + entity.length()),
    version_(buffer_(0, VERSION_SIZE)),
    key_(buffer_(VERSION_SIZE, VERSION_SIZE + config_.keyLength)),
    entity_(buffer_(VERSION_SIZE + config_.keyLength)),
    tag_(config_.tagLength) {

  checkArgument(key.length() == config_.keyLength, "Invalid key");

  version_[FORMAT_BYTE] = FORMAT_VALUE;
  version_[CONFIG_BYTE] = config_.id;

  // copy the data to memory I own
  key.copyTo(key_);
  entity.copyTo(entity_);

  ctx_ = (HMAC_CTX*) malloc(sizeof(HMAC_CTX));
  HMAC_CTX_init(ctx_);

  int code = HMAC_Init_ex(ctx_, key_.offset(0), config_.keyLength, config_.cipher, NULL);
  check(code == EVP_SUCCESS, "Mac context extended initialization failed");
}

MacEncoder::~MacEncoder() {
  /* void */ HMAC_CTX_cleanup(ctx_);
  free(ctx_);
}

Slice MacEncoder::start() {
  checkState(State::INITIAL, State::PROGRESS, "Start already called");
  update(version_);
  update(entity_);
  return buffer_(0, VERSION_SIZE);
}

void MacEncoder::write(Slice data) {
  checkState(State::PROGRESS, State::PROGRESS, "Encoding not in progress");
  update(data);
}

Slice MacEncoder::end() {
  checkState(State::PROGRESS, State::ENDED, "Encoding not in progress");

  unsigned int length;
  int code = HMAC_Final(ctx_, tag_.offset(0), &length);

  check(code == EVP_SUCCESS, "Mac tag generation failed");
  check(length == config_.tagLength, "Mac tag generated with wrong length");
  return tag_;
}

void MacEncoder::update(Slice slice) {
  int code = HMAC_Update(ctx_, slice.offset(0), slice.length());
  check(code == EVP_SUCCESS, "Mac encoding failed");
}

}}
