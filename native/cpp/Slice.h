// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <stdint.h>
#include <assert.h>
#include <cstring>
#include <iostream>
#include <type_traits>
#include <vector>

namespace facebook { namespace conceal {

/**
 * Slice (aka SliceOf<uint8_t>) represents a segment of a byte array.
 * It wraps an existing area in memory and controls access.
 * Also offers functionality to return other sub-segments over it.
 * This simplifies length/segment checks without poluting
 * other APIS: for example writing to an outputstream should be:
 * write(slice) and not write(slice, from, to).
 * The right way of indicating boundaries is to create a cheap sub-slice.
 *
 * Construction:
 * Slice(buffer, size);
 * Slice(buffer, offset, size);
 *
 * Sub-slices:
 * mySlice.slice(from, to); // from-inclusive, to-exclusive
 * Shorthands:
 * mySlice(from, to)
 * mySlice(from) -> mySlice(from, length)
 *
 * Non-modifiable versions of Slice can be created as: ConstSlice (aka SliceOf<const uint8_t>).
 * Those const versions don't allow mutating the underlying memory nor casting to mutable Slice.
 */
template<typename T>
class SliceOf {
 public:
  SliceOf(typename std::enable_if<std::is_arithmetic<T>::value, T*>::type buffer, size_t length)
    : SliceOf(buffer, 0, length) {}
  SliceOf(const SliceOf<T>& other) = default;
  SliceOf(SliceOf<T>&& other) = default;
  virtual ~SliceOf() {}

  // implicit copy from non-const to const
  template <typename U = T,
            typename std::enable_if<std::is_const<U>::value, U>::type* = nullptr>
  SliceOf(const SliceOf<typename std::remove_const<U>::type> nonConstSlice)
    : SliceOf(nonConstSlice.buffer_, 0, nonConstSlice.length_) {}

  // constructs Slice<const T> over a cont vector<T>
  // or a Slice<T> over a vector<T>
  // vector should not relocate its data or this will segfault!
  // this should be used only for local, non-changed vectors!
  template <typename U=T>
  explicit SliceOf(
    typename std::conditional<std::is_const<U>::value,
       const std::vector<typename std::remove_const<U>::type>&,
       std::vector<U>&
    >::type vector)
    : SliceOf(vector.data(), 0, vector.size()) {}

  SliceOf<T>& operator=(const SliceOf<T>& other) = default;
  SliceOf<T>& operator=(SliceOf<T>&& other) = default;

  T& operator[](size_t i) {
  //  DCHECK(i < length_);
    return buffer_[from_ + i];
  }

  SliceOf<T> operator()(size_t from) {
    // slice method will check boundaries
    return slice(from, length_);
  }

  SliceOf<T> operator()(size_t from, size_t to) {
    // slice method will check boundaries
    return slice(from, to);
  }

  bool operator==(const SliceOf<T>& s2) const {
    if (length_ != s2.length_) {
      return false;
    }
    return memcmp(offset(0), s2.offset(0), sizeof(T) * length_) == 0;
  }

  friend std::ostream& operator<<(std::ostream& os, const SliceOf<T>& slice) {
    return os.write((char*) slice.offset(0), sizeof(T) * slice.length_);
  }

  friend std::istream& operator>>(std::istream& is, SliceOf<T>& slice) {
    return is.read((char*) slice.offset(0), sizeof(T) * slice.length_);
  }

  size_t length() const { return length_; }

  SliceOf<T> slice(size_t from, size_t to) {
    // DCHECK(from <= to && to <= length_);
    SliceOf<T> result(buffer_, from_ + from, to - from);
    return result;
  }

  T* offset(size_t offset) {
    // DCHECK(offset < length_);
    return buffer_ + from_ + offset;
  }

  void copyTo(SliceOf<typename std::remove_const<T>::type> target) const {
    assert(target.length_ == length_);
    // memmove takes into account overlapping areas if any
    memmove(target.buffer_ + target.from_, buffer_ + from_, sizeof(T) * length_);
  }

  // const versions for not-necessarily-const methods
  const T& operator[](size_t i) const {
    // DCHECK(i < length_);
    return buffer_[from_ + i];
  }

  const SliceOf<T> operator()(size_t from) const {
    // slice method will check boundaries
    return slice(from, length_);
  }

  const SliceOf<T> operator()(size_t from, size_t to) const {
    // slice method will check boundaries
    return slice(from, to);
  }

  const SliceOf<T> slice(size_t from, size_t to) const {
    // DCHECK(from <= to && to <= length_);
    const SliceOf<T> result(buffer_, from_ + from, to - from);
    return result;
  }

  const T* offset(size_t offset) const {
    // DCHECK(offset < length_);
    return buffer_ + from_ + offset;
  }

 private:
   SliceOf(T* buffer, size_t from, size_t length)
       : buffer_(buffer), from_(from), length_(length) {}

   // the const version is my friend, so it can copy values onto me
   friend SliceOf<typename std::add_const<T>::type>;
  T* buffer_;
  size_t from_;
  size_t length_;
};

using Slice = SliceOf<uint8_t>;
using ConstSlice = SliceOf<const uint8_t>;

}}
