// Copyright 2004-present Facebook. All Rights Reserved.

#include "TransformBuffer.h"

namespace facebook { namespace conceal {

TransformBuffer::TransformBuffer(std::streambuf* delegate):
    std::streambuf(),
    delegate_(delegate),
    currentCharAvailable_(false) {
}

TransformBuffer::int_type TransformBuffer::underflow() {
  if (!currentCharAvailable_) {
    currentChar_ = delegate_->sbumpc();
    if (currentChar_ != traits_type::eof()) {
      char c = currentChar_;
      transform(&c, 1);
      currentChar_ = c;
      currentCharAvailable_ = true;
    }
  }
  // it can be EOF
  return currentChar_;
}

TransformBuffer::int_type TransformBuffer::uflow() {
  if (currentCharAvailable_) {
    currentCharAvailable_ = false;
    return currentChar_;
  }
  int result = delegate_->sbumpc();
  if (result != traits_type::eof()) {
    char data = (char) result;
    transform(&data, 1);
    result = data;
  }
  return result;
}

std::streamsize TransformBuffer::xsgetn(char* data, std::streamsize n) {
  if (n <= 0) {
    return 0;
  }
  if (currentCharAvailable_) {
    // currentChar is NOT eof (see underflow())
    data[0] = (char) currentChar_;
    currentCharAvailable_ = false;
    std::streamsize remaining = xsgetn(data+1, n-1);
    return remaining > 0 ? remaining + 1 : 1;
  }
  int result = delegate_->sgetn(data, n);
  if (result > 0) {
    transform(data, result);
  }
  return result;
}

}}
