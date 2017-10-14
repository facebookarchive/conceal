// Copyright 2004-present Facebook. All Rights Reserved.

#include <conceal/Buffer.h>
#include <gtest/gtest.h>
#include "SliceTestHelpers.h"

namespace facebook { namespace conceal {

TEST(BufferTest, UseAndSlice) {
  Buffer buffer(50);
  Buffer otro(30);

  fillRange(buffer);

  Slice s1 = buffer;
  Slice s2 = s1(10,20);
  Slice s3 = buffer(15);

  EXPECT_EQ(50, buffer.length());
  EXPECT_EQ(10, s2.length());
  EXPECT_EQ(35, s3.length());
  EXPECT_EQ(buffer.offset(0), s1.offset(0));
  EXPECT_EQ(buffer.offset(10), s2.offset(0));
  EXPECT_EQ(buffer.offset(15), s3.offset(0));
  EXPECT_EQ(buffer[5], s1[5]);

  s3[0] = 100;
  s3[1] = 101;

  EXPECT_EQ(100, s1[15]);
  EXPECT_EQ(101, s1[16]);
  EXPECT_EQ(100, buffer[15]);
  EXPECT_EQ(101, buffer[16]);
}

TEST(BufferTest, Move) {
  Buffer buffer(50);
  Buffer other(30);

  uint8_t* addressBuffer = buffer.offset(0);
  uint8_t* addressOther = other.offset(0);

  Slice slice = buffer(10, 20);

  EXPECT_EQ(50, buffer.length());
  EXPECT_EQ(30, other.length());
  EXPECT_NE(addressBuffer, addressOther);

  other = std::move(buffer);

  EXPECT_EQ(50, other.length());
  EXPECT_EQ(addressBuffer, other.offset(0));

  // slice still access the buffer owned originally by buffer (now by "other")
  EXPECT_EQ(addressBuffer + 10, slice.offset(0));
}

TEST(SliceTest, ConstSliceFromBuffer) {
  Buffer buffer(20);
  buffer[0] = 'a';
  ASSERT_EQ('a', buffer[0]);

  ConstSlice constSlice(buffer);
  buffer[0] = 'x';
  ASSERT_EQ('x', buffer[0]);
  ASSERT_EQ('x', constSlice[0]);
}

}}
