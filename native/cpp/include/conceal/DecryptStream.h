// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include "TailBuffer.h"
#include "TransformBuffer.h"
#include "Decrypt.h"
#include <streambuf>
#include <istream>

namespace facebook { namespace conceal {

class DecryptBuffer: public TransformBuffer {
public:
  DecryptBuffer(std::streambuf* source, Decrypt&& decrypt, CryptoConfig config);
  bool start();
  bool validTag();
protected:
  void transform(char* data, int n) override;
  int_type underflow() override;
  int_type uflow() override;
  std::streampos seekpos(
      std::streampos sp,
      std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override;
  std::streampos seekoff(
      std::streamoff off,
      std::ios_base::seekdir way,
      std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override;
  std::streamsize xsgetn(char* data, std::streamsize n) override;
private:
  enum TagState {NOT_CHECKED, VALID_TAG, INVALID_TAG};
  TailBuffer tailBuffer_;
  Decrypt decrypt_;
  size_t headerSize_;
  TagState tagState_;
  std::streamoff pos_;
  std::unique_ptr<char[]> skipBuffer_;
  bool checkEof(bool eofFound);
  void skip(std::streamoff off);
};

struct BaseDecryptStream {
  std::unique_ptr<std::istream> stream_;
  DecryptBuffer buffer_;
  BaseDecryptStream(std::streambuf* source, Decrypt&& decrypt, CryptoConfig config);
  BaseDecryptStream(std::unique_ptr<std::istream> source, Decrypt&& decrypt, CryptoConfig config);
};

class DecryptStream: private BaseDecryptStream, public std::istream {
public:
  DecryptStream(std::unique_ptr<std::istream> source, Decrypt&& decrypt, CryptoConfig config);
  DecryptStream(std::streambuf* source, Decrypt&& decrypt, CryptoConfig config);
  bool start();
  /**
   * Streams don't seem to play well with exceptions... so let's inform of tag validity with a bool
   */
  bool validTag();
};

}}
