// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include "Buffer.h"
#include <streambuf>

namespace facebook { namespace conceal {

/**
 * Wrapper implementation of std::streambuf (only for reading!) consumes and keeps a tail of a
 * fixed size. Byte copies are minimized. If caller request a big bunch of bytes they will be
 * returned directly to the client, and only tail-size array will be copied back.
 * <p>
 * Invariant:
 * - Buffer keeps a buffer with the current "tail" (as if delegate is EOF)
 * - Buffer has 2x tail size "extra" room for byte-moving
 *
 * TailBuffer object:
 * [buffer_                                   ] // allocated
 * [tail_        ][extra_                     ] // view over the same bytes
 * If 200 bytes were already returned to client, tail will have bytes [200,200+tailSize).
 * Check the implementation comments to see how it's implemented.
 */
class  TailBuffer: public std::streambuf {
 public:
  TailBuffer(std::streambuf* delegate, size_t tailSize);
  bool start();
  Slice tail();
 protected:
  // don't peek on this buffer
  TailBuffer::int_type underflow() override;
  TailBuffer::int_type uflow() override;
  std::streamsize xsgetn(char* data, std::streamsize n) override;
 private:
  std::streambuf* delegate_;
  size_t tailSize_;
  Buffer buffer_;
  Slice tail_;
  Slice extra_;
  std::streamsize smallConsume(Slice result);
  std::streamsize largeConsume(Slice result);
};

}}
