// Copyright 2004-present Facebook. All Rights Reserved.

#include "EncryptStream.h"

namespace facebook { namespace conceal {

EncryptBuffer::EncryptBuffer(std::streambuf* sink, Encrypt&& encrypt, std::size_t buff_sz) :
    sink_(*sink),
    encrypt_(std::move(encrypt)),
    buffer_(buff_sz + 1)
{
  char* base = reinterpret_cast<char*>(&buffer_[0]);
  setp(base, base + buff_sz); // -1 to make overflow() easier
}

void EncryptBuffer::start() {
  Slice header = encrypt_.start();
  sink_.sputn(reinterpret_cast<char*>(&header[0]), header.length());
}

void EncryptBuffer::end() {
  encryptAndFlush();
  Slice tail = encrypt_.end();
  sink_.sputn(reinterpret_cast<char*>(&tail[0]), tail.length());
}

EncryptBuffer::int_type EncryptBuffer::overflow(int_type ch)
{
  if (ch != traits_type::eof())
  {
    // this is an invariant
    assert(std::less_equal<char*>()(pptr(), epptr()));
    *pptr() = ch;
    pbump(1);
    encryptAndFlush();
  }
  return ch;
}

void EncryptBuffer::encryptAndFlush() {
  std::ptrdiff_t n = pptr() - pbase();
  if (n > 0) {
    Slice slice = buffer_(0, n);
    encrypt_.write(slice, slice);
    pbump(-n);
    sink_.sputn(pbase(), n);
  }
}

int EncryptBuffer::sync()
{
	encryptAndFlush();
  return sink_.pubsync();
}

BaseEncryptStream::BaseEncryptStream(std::ostream* sink, Encrypt&& encrypt, size_t bufferSize):
    buffer_(sink->rdbuf(), std::move(encrypt), bufferSize) {
}

EncryptStream::EncryptStream(std::ostream* sink, Encrypt&& encrypt, size_t bufferSize):
    BaseEncryptStream(sink, std::move(encrypt), bufferSize),
    std::ostream(&buffer_) {
  buffer_.start();
}

void EncryptStream::end() {
  buffer_.end();
}

}}
