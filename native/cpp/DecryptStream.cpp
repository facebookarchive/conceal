// Copyright 2004-present Facebook. All Rights Reserved.

#include "DecryptStream.h"

namespace facebook { namespace conceal {

inline bool DecryptBuffer::checkEof(bool eofFound) {
  if (eofFound && tagState_ == NOT_CHECKED) {
    bool ok = decrypt_.end(tailBuffer_.tail());
    tagState_ = ok ? VALID_TAG : INVALID_TAG;
  }
  return eofFound;
}

DecryptBuffer::DecryptBuffer(std::streambuf* source, Decrypt&& decrypt, CryptoConfig config):
    TransformBuffer(&tailBuffer_),
    tailBuffer_(source, config.tagLength),
    decrypt_(std::move(decrypt)),
    headerSize_(2 + config.ivLength),
    tagState_(NOT_CHECKED),
    pos_(0),
    skipBuffer_(nullptr) {
}

bool DecryptBuffer::start() {
  if (!tailBuffer_.start()) {
    return false;
  }
  Buffer header(headerSize_);
  std::streamsize count =
      tailBuffer_.sgetn(reinterpret_cast<char*>(&header[0]), header.length());
  if (count < 0 || (unsigned) count != header.length()) {
    return false;
  }
  decrypt_.start(header);
  return true;
}

void DecryptBuffer::transform(char* data, int n) {
  Slice slice(reinterpret_cast<uint8_t*>(data), n);
  decrypt_.read(slice, slice);
}

bool DecryptBuffer::validTag() {
  return tagState_ == VALID_TAG;
}

DecryptBuffer::int_type DecryptBuffer::underflow() {
  // pos_ does not change
  int_type result = TransformBuffer::underflow();
  checkEof(result == traits_type::eof());
  return result;
}

DecryptBuffer::int_type DecryptBuffer::uflow() {
  // pos_ does change
  int_type result = TransformBuffer::uflow();
  if (!checkEof(result == traits_type::eof())) {
    pos_++;
  }
  return result;
}

std::streamsize DecryptBuffer::xsgetn(char* data, std::streamsize n) {
  std::streamsize result = TransformBuffer::xsgetn(data, n);
  if (!checkEof(result != n)) {
    pos_ += result;
  }
  return result;
}

std::streampos DecryptBuffer::seekpos(std::streampos sp, std::ios_base::openmode which) {
  // we always assume ios_base::in, and possitive sp (doesn't make sense a negative one)
  // if we're not at EOF and requested position is forward... use relative seek.
  if (pos_ >= 0 && pos_ <= sp) {
    return seekoff(sp - pos_, std::ios_base::cur);
  }
  // otherwise default behavior (just EOF)
  return TransformBuffer::seekpos(sp, which);
}

std::streampos DecryptBuffer::seekoff(
    std::streamoff off,
    std::ios_base::seekdir way,
    std::ios_base::openmode which) {
  if (off < 0) {
    // cannot handle negative seek, go to default behavior
    return TransformBuffer::seekoff(off, way, which);
  }
  switch(way) {
    case std::ios_base::beg:
      // relative to beginning is the same as absolute seek
      return seekpos(off, which);
    case std::ios_base::cur:
      // relative to current position, do it by decrypting
      skip(off);
      return pos_;
    default:
      // from end or undefined
      return TransformBuffer::seekoff(off, way, which);
  }
}

constexpr int SKIP_BUFFER_SIZE = 1024;

void DecryptBuffer::skip(std::streamoff off) {
  if (skipBuffer_ == nullptr) {
    skipBuffer_ = std::make_unique<char[]>(SKIP_BUFFER_SIZE);
  }
  while (off > 0) {
    std::streamsize chunkSize = std::min(off, std::streamoff(SKIP_BUFFER_SIZE));
    std::streamsize skipped = this->xsgetn(skipBuffer_.get(), off);
    if (checkEof(skipped != chunkSize)) {
      break;
    }
    off -= skipped;
  }
}

BaseDecryptStream::BaseDecryptStream(
    std::streambuf* source,
    Decrypt&& decrypt,
    CryptoConfig config)
  : stream_(nullptr),
    buffer_(source, std::move(decrypt), config) {}

BaseDecryptStream::BaseDecryptStream(
    std::unique_ptr<std::istream> source,
    Decrypt&& decrypt,
    CryptoConfig config)
  : stream_(std::move(source)),
    buffer_(stream_->rdbuf(), std::move(decrypt), config) {}

DecryptStream::DecryptStream(std::streambuf* source, Decrypt&& decrypt, CryptoConfig config):
    BaseDecryptStream(source, std::move(decrypt), config),
    std::istream(&buffer_) {}

DecryptStream::DecryptStream(
    std::unique_ptr<std::istream> source,
    Decrypt&& decrypt,
    CryptoConfig config)
  : BaseDecryptStream(std::move(source), std::move(decrypt), config),
    std::istream(&buffer_) {}

bool DecryptStream::start() {
  return buffer_.start();
}

bool DecryptStream::validTag() {
  return buffer_.validTag();
}

}}
