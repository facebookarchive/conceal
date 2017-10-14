// Copyright 2004-present Facebook. All Rights Reserved.

#include <gtest/gtest.h>

// Some tests I want to do on C++ i/o streams
#include <ostream>
#include <conceal/TransformBuffer.h>

#include "SliceTestHelpers.h"

namespace facebook { namespace conceal {

class Rot1Buffer: public TransformBuffer {
public:
  Rot1Buffer(std::streambuf* delegate):
      TransformBuffer(delegate) {}
protected:
  void transform(char* data, int n) {
    for (int i=0; i<n; i++) {
      data[i]++;
    }
  }
};

TEST(TransformBufferTest, PrintInputOps) {
  std::ostringstream strout{};
  for (int i=0; i<80; i++) {
    strout <<
      "Some very long content so I am sure it will be read in several chunks "
      "and I can confirm the transform works flawlessly with reading one char or 1000.\n";
  }
  std::string content = strout.str();
  std::stringbuf fbuf{content};
  Rot1Buffer buf{&fbuf};
  std::istream stream(&buf);
  int firstConsume = stream.get();
  EXPECT_EQ((int) ('S'+1), firstConsume);
  int total = 1;
  int size = 500;
  char data[size];
  while (!stream.eof()) {
    stream.read(data, size);
    int count = stream.gcount();
    for (int i=0; i<count; i++) {
      EXPECT_EQ(content[total+i] + 1, data[i]);
    }
    total += count;
  }
  EXPECT_EQ(content.size(), total);
}

/**
 * Tests that underflow works fine (char is kept... and gets transformed only once)
 */
TEST(TransformBufferTest, UnderflowTest) {
  Buffer content(40);
  fillRange(content);
  std::stringbuf sbuf{std::string(reinterpret_cast<char*>(&content[0]), 40)};
  Rot1Buffer rotBuffer{&sbuf};
  std::istream stream(&rotBuffer);
  int peek1 = stream.peek();
  EXPECT_EQ(1, peek1);
  int peek2 = stream.peek();
  EXPECT_EQ(1, peek2);
  int get1 = stream.get();
  EXPECT_EQ(1, get1);
  int get2 = stream.get();
  EXPECT_EQ(2, get2);
  char data[5];
  Slice dataSlice(reinterpret_cast<uint8_t*>(data), 5);
  stream.read(data, 5);
  EXPECT_EQ(5, stream.gcount());
  EXPECT_EQ((char) 3, data[0]);
  EXPECT_EQ((char) 4, data[1]);
  EXPECT_EQ((char) 5, data[2]);
  EXPECT_EQ((char) 6, data[3]);
  EXPECT_EQ((char) 7, data[4]);
  int peek3 = stream.peek();
  EXPECT_EQ(8, peek3);
  int peek4 = stream.peek();
  EXPECT_EQ(8, peek4);
  while(stream && !stream.eof()) {
    stream.read(data, 5);
  }
  EXPECT_TRUE(stream.eof());
  EXPECT_EQ(Rot1Buffer::traits_type::eof(), stream.peek());
  EXPECT_EQ(Rot1Buffer::traits_type::eof(), stream.peek());
}

}}
