// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <streambuf>

namespace facebook { namespace conceal {

/**
 * Base class for stream-buffers that transform the return data without any real buffering.
 * Byte handling for streams in C++ happen at buffer level.
 * This is a buffer-wrapper that allows for any transformation.
 * It doesn't implement any extra buffering, so no look-ahead is possible.
 * If look-ahead is needed it can be wrapped with another buffer on top.
 * <p>
 * No look-ahead:
 * istream( ZeroBuffer(transform) -> original-buffer )
 * If read ahead is needed:
 * istream( DelegateBuffer -> ZeroBuffer(transform) -> original-buffer )
 * <p>
 * It doesn't support pos/seek
 */
class TransformBuffer: public std::streambuf {
public:
  explicit TransformBuffer(std::streambuf* delegate);
private:
  std::streambuf* delegate_;
  TransformBuffer::int_type currentChar_;
  bool currentCharAvailable_;
protected:
  // don't peek on this buffer
  TransformBuffer::int_type underflow() override;
  TransformBuffer::int_type uflow() override;
  std::streamsize xsgetn(char* data, std::streamsize n) override;
  /*
   * implement this one to transform the data returned on each read
   */
  virtual void transform(char* data, int n)=0;
};

}}
