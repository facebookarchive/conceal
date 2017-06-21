// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include "Slice.h"
#include <memory>
#include <type_traits>

namespace facebook { namespace conceal {

/**
 * Handy way to declare buffers of a given size.
 *
 * Instead of manually allocating and wrapping with Slice do:
 * Buffer b(size); // b works as a Slice over itself
 * Buffer object is the owner of the memory.
 * Any Slice over it will be valid as long as Buffer is still valid.
 *
 * Example:
 * {
 * Buffer buffer(50);
 *   Slice s1 = buffer(10,20);
 *   Slice s2 = buffer(40);
 *   // use s1 and s2
 *
 * } // buffer is freed, therefore s1 and s2 are not valid anymore
 *
 * This object is also useful to return data with length as it implements
 * move semantics.
 * Buffer buffer = createBufferFromHexString("deadbeefcafebabe");
 */
template <typename T>
class BufferOf: public SliceOf<typename std::enable_if<!std::is_const<T>::value, T>::type> {
 public:
  explicit BufferOf(size_t size)
   : SliceOf<T>(new T[size], size),
     buffer_(std::unique_ptr<T[]>(this->offset(0))) {
  }
  BufferOf(const BufferOf<T>& other) = delete;
  BufferOf(BufferOf<T>&& other) = default;

  BufferOf<T>& operator=(const BufferOf<T>& other) = delete;
  BufferOf<T>& operator=(BufferOf<T>&& other) = default;
private:
 std::unique_ptr<T[]> buffer_;
};

using Buffer = BufferOf<uint8_t>;

}}
