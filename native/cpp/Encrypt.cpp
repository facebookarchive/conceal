// Copyright 2004-present Facebook. All Rights Reserved.

#include "Encrypt.h"
#include "CryptoException.h"

#include <stdexcept>

namespace facebook { namespace conceal {

// format indexes and sizes
constexpr int VERSION_SIZE = 2;
constexpr int FORMAT_BYTE = 0;
constexpr int FORMAT_VALUE = 1; // only format
constexpr int CONFIG_BYTE = 1;

constexpr int EVP_SUCCESS = 1; // Init, Update and Final all return 1 for success

Encrypt::Encrypt(CryptoConfig config, Slice key, Slice iv, Slice entity):
    WithState(State::INITIAL),
    config_(config),
    buffer_(VERSION_SIZE + config.ivLength + config.keyLength),
    version_(buffer_(0, VERSION_SIZE)),
    iv_(buffer_(VERSION_SIZE, VERSION_SIZE + config.ivLength)),
    key_(buffer_(VERSION_SIZE + config.ivLength, VERSION_SIZE + config.ivLength + config.keyLength)),
    entity_(entity.length()),
    tag_(config_.tagLength) {

  checkArgument(key.length() == config_.keyLength, "Invalid key");
  checkArgument(iv.length() == config_.ivLength, "Invalid IV");

  version_[FORMAT_BYTE] = FORMAT_VALUE;
  version_[CONFIG_BYTE] = config_.id;

  // copy the data to memory I own
  iv.copyTo(iv_);
  key.copyTo(key_);
  entity.copyTo(entity_);

  const EVP_CIPHER* cipher = config_.cipher;
  ctx_ = EVP_CIPHER_CTX_new();
  check(ctx_, "Encryption context creation failed");
  int code = EVP_EncryptInit_ex(ctx_, cipher, NULL, NULL, NULL);
  check(code == EVP_SUCCESS, "Encryption context creation failed (cipher)");
  code = EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_IVLEN, config_.ivLength, NULL);
  check(code == EVP_SUCCESS, "Encryption context creation failed (IV length)");
  code = EVP_EncryptInit_ex(ctx_, NULL, NULL, key_.offset(0), iv_.offset(0));
  check(code == EVP_SUCCESS, "Encryption initialization failed");
}

Encrypt::Encrypt(Encrypt&& other)
  : WithState(other),
  config_(other.config_),
  buffer_(std::move(other.buffer_)),
  version_(std::move(other.version_)),
  iv_(std::move(other.iv_)),
  key_(std::move(other.key_)),
  entity_(std::move(other.entity_)),
  tag_(std::move(other.tag_)) {
    ctx_ = other.ctx_;
    other.ctx_ = nullptr;
  }

Encrypt::~Encrypt() {
  if (ctx_ != nullptr) {
    /* void */ EVP_CIPHER_CTX_free(ctx_);
  }
}

Slice Encrypt::start() {
  checkState(State::INITIAL, State::PROGRESS, "Start already called");

  updateAad(version_);
  updateAad(entity_);
  return buffer_(0, VERSION_SIZE + config_.ivLength);
}

void Encrypt::write(Slice src, Slice target) {
  checkArgument(src.length() == target.length(), "Target slice is the same length as src slice");
  checkState(State::PROGRESS, State::PROGRESS, "Encryption not in progress");

  int bytesWritten;
  int code = EVP_CipherUpdate(ctx_, target.offset(0), &bytesWritten, src.offset(0), src.length());
  check(code == EVP_SUCCESS, "Chunk encryption failed");
  // GCM will output exactly the same amount of bytes
  check(bytesWritten == static_cast<int>(src.length()),
      "CipherUpdate didn't encrypt the exact chunk");
}

Slice Encrypt::end() {
  checkState(State::PROGRESS, State::ENDED, "Encryption not in progress");

  int bytesWritten;
  int code = EVP_EncryptFinal_ex(ctx_, tag_.offset(0), &bytesWritten);
  check(code == EVP_SUCCESS, "Encryption finalization failed");

  if (bytesWritten != 0) {
    // according to https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
    // GCM doesn't produce any extra output (even with partial blocks)
    // Look for this text in sample:
    /* Finalise the encryption. Normally ciphertext bytes may be written at
  	 * this stage, but this does not occur in GCM mode
  	 */
    throw std::runtime_error("Encryption (GCM) outputted unexpected bytes");
  }
  code = EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_GET_TAG, tag_.length(), tag_.offset(0));
  check(code == EVP_SUCCESS, "Tag generation failed");
  return tag_;
}

int Encrypt::updateAad(Slice slice) {
  int bytesWritten;
  int code = EVP_CipherUpdate(ctx_, NULL, &bytesWritten, slice.offset(0), slice.length());
  check(code == EVP_SUCCESS, "Aad update failed");
  return bytesWritten;
}

}}
