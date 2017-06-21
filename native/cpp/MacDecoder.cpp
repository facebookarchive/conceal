// Copyright 2004-present Facebook. All Rights Reserved.

#include "MacDecoder.h"
#include "SliceMethods.h"

namespace facebook { namespace conceal {

// format indexes and sizes
constexpr int VERSION_SIZE = 2;
constexpr int FORMAT_BYTE = 0;
constexpr int FORMAT_VALUE = 1; // only format
constexpr int CONFIG_BYTE = 1;

constexpr int EVP_SUCCESS = 1; // Init, Update and Final all return 1 for success

// we use this message for any error to prevent leaking information to an attacker
// argument and state errors are already know by client, so those are ok
const char* GENERIC_ERROR_MESSAGE = "Error decoding";

MacDecoder::MacDecoder(MacConfig config, Slice key, Slice entity)
  : WithState(State::INITIAL),
    config_(config),
    buffer_(VERSION_SIZE + config_.keyLength + entity.length()),
    version_(buffer_(0, VERSION_SIZE)),
    key_(buffer_(VERSION_SIZE, VERSION_SIZE + config_.keyLength)),
    entity_(buffer_(VERSION_SIZE + config_.keyLength)) {

  checkArgument(key.length() == key_.length(), "Invalid key length");

  // copy data to own it
  key.copyTo(key_);
  entity.copyTo(entity_);

  ctx_ = (HMAC_CTX*) malloc(sizeof(HMAC_CTX));
  HMAC_CTX_init(ctx_);
  int code = HMAC_Init_ex(ctx_, key_.offset(0), config_.keyLength, config_.cipher, NULL);
  check(code == EVP_SUCCESS, GENERIC_ERROR_MESSAGE);
}

MacDecoder::~MacDecoder() {
  /* void */ HMAC_CTX_cleanup(ctx_);
  free(ctx_);
}

void MacDecoder::start(Slice header) {
  checkState(State::INITIAL, State::PROGRESS, "Decoding already started");
  checkArgument(header.length() == VERSION_SIZE, "Invalid header length");

  header.copyTo(version_);
  checkArgument(version_[FORMAT_BYTE] == FORMAT_VALUE, "Invalid format");
  checkArgument(version_[CONFIG_BYTE] == config_.id, "Invalid MacConfig");

  update(version_);
  update(entity_);
}

void MacDecoder::read(Slice data) {
  checkState(State::PROGRESS, State::PROGRESS, "Decoding not in progress");
  update(data);
}

bool MacDecoder::end(Slice tail) {
  checkState(State::PROGRESS, State::ENDED, "Decoding not in progress");
  checkArgument(tail.length() == config_.tagLength, "Invalid tail");

  Buffer tag(config_.tagLength);
  unsigned int length;
  int code = HMAC_Final(ctx_, tag.offset(0), &length);

  check(code == EVP_SUCCESS, GENERIC_ERROR_MESSAGE);
  check(length == config_.tagLength, GENERIC_ERROR_MESSAGE);

  return SliceMethods::equalsConstantTime(tail, tag);
}

void MacDecoder::update(Slice slice) {
  int code = HMAC_Update(ctx_, slice.offset(0), slice.length());
  check(code == EVP_SUCCESS, GENERIC_ERROR_MESSAGE);
}

}}
