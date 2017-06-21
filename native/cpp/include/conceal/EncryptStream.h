// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include "Encrypt.h"
#include <ostream>

namespace facebook { namespace conceal {

/**
 * Wrapper of istream that encrypts on the fly.
 * It delegates to another stream/buffer.
 * Typical use:
 * // setup
 * ifstream fileStream(...); // you could create just the file buffer (or any other buffer)
 * Encrypt encrypt(CryptoConfig::CONFIG_256(), key, iv); // the encryption to use
 * EncryptStream encryptStream(fileStream.rdbuf(), encrypt);
 * // use
 * encryptStream.start();    // header is written
 * encryptStream.write(...); // write all the plain data you want
 * encryptStream.end();      // it output's the final tag used to verify integrity later
 */
class EncryptBuffer: public std::streambuf {
 public:
  explicit EncryptBuffer(std::streambuf* sink, Encrypt&& encrypt, std::size_t buff_sz = 256);
  EncryptBuffer(const EncryptBuffer&) = delete;
  EncryptBuffer& operator=(const EncryptBuffer&) = delete;

  /**
   * The stream must be started before use.
   */
  void start();
  /**
   * end() will finish the encryption and add the integrity-check tail.
   */
  void end();
 protected:
  // buffer method overrides
  int_type overflow(int_type ch) override;
  int sync() override;
 private:
  std::streambuf& sink_;
  Encrypt encrypt_;
  Buffer buffer_;
  void encryptAndFlush();
};

struct BaseEncryptStream {
  BaseEncryptStream(std::ostream* sink, Encrypt&& encrypt, size_t bufferSize);
  EncryptBuffer buffer_;
};

class EncryptStream: private BaseEncryptStream, public std::ostream {
 public:
  EncryptStream(std::ostream* sink, Encrypt&& encrypt, size_t bufferSize);
  void end();
};

}}
