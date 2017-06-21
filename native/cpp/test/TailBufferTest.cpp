// Copyright 2004-present Facebook. All Rights Reserved.

#include <gtest/gtest.h>

// Some tests I want to do on C++ i/o streams
#include <ostream>
#include <conceal/TailBuffer.h>

#include "SliceTestHelpers.h"

namespace facebook { namespace conceal {

/**
 * Tests that underflow works ok.
 */
TEST(TailBufferTest, UnderflowTest) {
  Buffer content(50);
  fillRange(content);
  std::stringbuf sbuf{std::string(reinterpret_cast<char*>(&content[0]), content.length())};
  TailBuffer tailBuffer{&sbuf, 10};
  tailBuffer.start();
  std::istream stream(&tailBuffer);
  char data[15];
  Slice dataSlice(Slice(reinterpret_cast<uint8_t*>(data), 15));
  stream.read(data, 15);
  EXPECT_EQ(content(0, 15), dataSlice);
  int underflow1 = stream.peek();
  EXPECT_EQ(TailBuffer::traits_type::to_int_type(content[15]), underflow1);
  TailBuffer::int_type underflow2 = stream.peek();
  EXPECT_EQ(TailBuffer::traits_type::to_int_type(content[15]), underflow2);
  TailBuffer::int_type uflow1 = stream.get();
  EXPECT_EQ(TailBuffer::traits_type::to_int_type(content[15]), uflow1);
  TailBuffer::int_type uflow2 = stream.get();
  EXPECT_EQ(TailBuffer::traits_type::to_int_type(content[16]), uflow2);
  TailBuffer::int_type underflow3 = stream.peek();
  EXPECT_EQ(TailBuffer::traits_type::to_int_type(content[17]), underflow3);
  stream.read(data, 15);
  EXPECT_EQ(content(17, 32), dataSlice);
  stream.read(data, 15);
  EXPECT_EQ(8 /* 32 -> 40 */, stream.gcount());
  EXPECT_EQ(content(32, 40), dataSlice(0, 8));
  TailBuffer::int_type underflow4 = stream.peek();
  EXPECT_EQ(TailBuffer::traits_type::eof(), underflow4);
}

void testReading(char* content, const int length, const size_t tailSize, const int chunkSize) {
  std::stringbuf fbuf{std::string(content, length)};
  TailBuffer tailBuffer{&fbuf, tailSize};
  EXPECT_EQ(true, tailBuffer.start());
  std::istream stream(&tailBuffer);
  int total = 0;
  char expected = (char) 0;
  char result[chunkSize];
  while (!stream.eof()) {
    stream.read(result, chunkSize);
    int count = stream.gcount();
    for (int i=0; i<count; i++) {
      EXPECT_EQ(expected, result[i]);
      expected++;
    }
    total += count;
  }
  EXPECT_EQ(length - tailSize, total);
  EXPECT_EQ(
      Slice(reinterpret_cast<uint8_t*>(&content[length-tailSize]), tailSize),
      tailBuffer.tail());
}

TEST(TailBufferTest, FailToStart) {
  const int length = 15;
  char content[length];
  for (size_t tail=1; tail<length+10; tail++) {
    SCOPED_TRACE(testing::Message() << "length = " << length <<  ", tailSize = " << tail);
    std::stringbuf delegate{std::string(content, length)};
    TailBuffer tailBuffer{&delegate, tail};
    bool enoughData = tail <= length;
    bool ok = tailBuffer.start();
    EXPECT_EQ(enoughData, ok);
  }
}

TEST(TailBufferTest, ZeroDataWithGet) {
  const int length = 15;
  char content[length];
  for (int i=0; i<length; i++) {
    content[i] = (char) i;
  }
  std::stringbuf delegate{std::string(content, length)};
  TailBuffer tailBuffer{&delegate, length};
  bool ok = tailBuffer.start();
  EXPECT_EQ(true, ok);
  std::istream stream(&tailBuffer);
  int result = stream.get();
  EXPECT_EQ(EOF, result);
  EXPECT_EQ(Slice(reinterpret_cast<uint8_t*>(content), length), tailBuffer.tail());
}

TEST(TailBufferTest, ZeroDataWithRead) {
  const int length = 15;
  char content[length];
  for (int i=0; i<length; i++) {
    content[i] = (char) i;
  }
  std::stringbuf delegate{std::string(content, length)};
  TailBuffer tailBuffer{&delegate, length};
  bool ok = tailBuffer.start();
  EXPECT_EQ(true, ok);
  std::istream stream(&tailBuffer);
  char data[10];
  stream.read(data, 10);
  EXPECT_EQ(0, stream.gcount());
  EXPECT_TRUE(stream.eof());
  EXPECT_EQ(Slice(reinterpret_cast<uint8_t*>(content), length), tailBuffer.tail());
}

TEST(TailBufferTest, TailLoops) {
  const int length = 1000;
  char content[length];
  for (int i=0; i<length; i++) {
    content[i] = (char) i;
  }
  for (size_t tailSize=1; tailSize<16; tailSize++) {
    SCOPED_TRACE(testing::Message() << "tailSize = " << tailSize);
    for (int chunkSize=1; chunkSize<50; chunkSize++) {
      SCOPED_TRACE(testing::Message() << "chunkSize = " << chunkSize);
      testReading(content, length, tailSize, chunkSize);
    }
  }
}

}}
