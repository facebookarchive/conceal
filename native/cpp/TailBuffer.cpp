// Copyright 2004-present Facebook. All Rights Reserved.

#include "TailBuffer.h"

namespace facebook { namespace conceal {

TailBuffer::TailBuffer(std::streambuf* delegate, size_t tailSize):
    delegate_(delegate),
    tailSize_(tailSize),
    buffer_(tailSize * 3),
    tail_(buffer_(0, tailSize)),
    extra_(buffer_(tailSize, tailSize * 3)) {
}

bool TailBuffer::start() {
  std::streamsize count = delegate_->sgetn(reinterpret_cast<char*>(&tail_[0]), tail_.length());
  return (count > 0) && (((size_t) count) == tailSize_);
}

Slice TailBuffer::tail() {
  return tail_;
}

TailBuffer::int_type TailBuffer::underflow() {
  int_type sourceUnderflow = delegate_->sgetc();
  if (sourceUnderflow == traits_type::eof()) {
    // if delegate doesn't have more, we don't have more
    return traits_type::eof();
  } else {
    // if delegate does have more, we would return first from tail
    return tail_[0];
  }
}

TailBuffer::int_type TailBuffer::uflow() {
  char data;
  std::streamsize count = xsgetn(&data, 1);
  return count == 1 ? traits_type::to_int_type(data) : traits_type::eof();
}

std::streamsize TailBuffer::xsgetn(char* data, std::streamsize n) {
  assert(n >= 0);
  Slice result(reinterpret_cast<uint8_t*>(data), n);
  if (result.length() < tailSize_ * 2) {
    return smallConsume(result);
  } else {
    return largeConsume(result);
  }
}

/*
 * Small-read: up to tailSize x 2 (exclusive)
 *                                                tail[abcd] extra[........]
 * - extra room in buffer is filled from delegate tail[abcd] extra[efghijkl]
 * - up to tailSize x 2 is copied to caller       result[abcdefg]
 * - tailSize is shifted to beginning of buffer   tail[ijkl] extra[........]
 */
std::streamsize TailBuffer::smallConsume(Slice result) {
  assert(result.length() < tailSize_ * 2);
  std::streamsize count = delegate_->sgetn(reinterpret_cast<char*>(&extra_[0]), result.length());
  buffer_(0, count).copyTo(result(0, count));
  buffer_(count, count + tailSize_).copyTo(tail_);
  // the same amount of bytes consumed from delegates, will be returned to client (even if EOF)
  return count;
}

/*
 * Big-read: from tailSize x 2 (inclusive)
 *                                                                      tail[abcd] extra[........]
 * - tailSize is copied to client                                       result[abcd............]
 * - count - tailSize is copied from delegate directly to client        result[abcdefghijklmnop]
 * - tailSize is copied from delegate to buffer                         tail[qrst] extra[........]
 * - if EOF before count is provided... tailSize is copied back to buffer
 */
std::streamsize TailBuffer::largeConsume(Slice result) {
  tail_.copyTo(result(0, tailSize_));
  std::streamsize remaining = result.length() - tailSize_;
  std::streamsize count =
      delegate_->sgetn(reinterpret_cast<char*>(&result[tailSize_]), remaining);
  if (count < 1) {
    // 0 or EOF, no data returned
    return count;
  }
  if (count < remaining) {
    // if I cound't read remaining, we just hit EOF, keep the tail
    // return the tail to the buffer
    result(count, count + tailSize_).copyTo(tail_);
    // we don't fully read, it's always tailSize less... xsgetn will be called again and filled
    // it can be improved a tiny bit to return all and it'd prevent 1 tailSize copy...
    return count;
  }
  // if we could read all, we try to read also a whole tail
  std::streamsize tailCount = delegate_->sgetn(reinterpret_cast<char*>(&tail_[0]), tail_.length());
  if (tailCount > 0 && (((size_t) tailCount) == tailSize_)) {
    // if whole new tail was read, great, we're done
    return count + tailSize_;
  }
  // I will need to copy back some tail from the result
  int tailBack = tailSize_;
  if (tailCount > 0) {
    // if some tail was read, move it to the correct place
    tail_(0, tailCount).copyTo(tail_(tailSize_ - tailCount, tailSize_));
    tailBack = tailSize_ - tailCount;
  }
  // copy back from result what should be part of tail
  result(result.length() - tailBack, result.length()).copyTo(tail_(0, tailBack));
  // now we're good
  return result.length() - tailBack;
}

}}
