// Copyright 2004-present Facebook. All Rights Reserved.

#include <gtest/gtest.h>
#include <conceal/Slice.h>

namespace facebook { namespace conceal {

TEST(SliceTest, Lengths) {
  uint8_t buffer[23];
  Slice slice(buffer, 23);
  EXPECT_EQ(23, slice.length());
  EXPECT_EQ(16, slice.slice(2,18).length());
}

TEST(SliceTest, ConstLengths) {
  uint8_t buffer[23];
  const Slice slice(buffer, 23);
  EXPECT_EQ(23, slice.length());
  Slice notconst = slice.slice(2,18);
  EXPECT_EQ(16, slice.slice(2,18).length());
}

TEST(SliceTest, Sharing) {
  uint8_t buffer[23];
  Slice slice(buffer, 23);
  Slice sub1 = slice(0,10);
  Slice sub2 = slice(2,20);
  // sub1 has same addresses
  EXPECT_EQ(slice.offset(0), sub1.offset(0));
  EXPECT_EQ(slice.offset(5), sub1.offset(5));
  // sub2 has +2 addresses
  EXPECT_EQ(slice.offset(2), sub2.offset(0));
  EXPECT_EQ(slice.offset(12), sub2.offset(10));
}

TEST(SliceTest, ConstSharing) {
  uint8_t buffer[23];
  const Slice slice(buffer, 23);
  Slice sub1 = slice(0,10);
  Slice sub2 = slice(2,20);
  // sub1 has same addresses
  EXPECT_EQ(slice.offset(0), sub1.offset(0));
  EXPECT_EQ(slice.offset(5), sub1.offset(5));
  // sub2 has +2 addresses
  EXPECT_EQ(slice.offset(2), sub2.offset(0));
  EXPECT_EQ(slice.offset(12), sub2.offset(10));
}

TEST(SliceTest, Index) {
  uint8_t buffer[10];
  Slice slice(buffer, 10);
  const Slice constSlice = slice;

  for (int i=0; i<slice.length(); i++) {
    // this relies on offset
    *slice.offset(i) = i;
    // check reading
    EXPECT_EQ(i, slice[i]);
    EXPECT_EQ(i, constSlice[i]);
    // check address
    EXPECT_EQ(slice.offset(i), &slice[i]);
    EXPECT_EQ(slice.offset(i), constSlice.offset(i));
    // check assignment
    slice[i] = 2*i;
    EXPECT_EQ(2*i, slice[i]);
    EXPECT_EQ(2*i, constSlice[i]);
  }
}

TEST(SliceTest, Parenthesis) {
  uint8_t buffer[23];
  Slice slice(buffer, 23);

  for (int i=0; i<slice.length(); i++) {
    slice[i] = i;
  }
  Slice other = slice(4, 20);
  Slice other2 = slice(4);

  EXPECT_EQ(slice(4, 20), other);
  EXPECT_EQ(slice(4, 23), other2);
}

void fill(Slice slice, int from) {
  for (int i=0; i<slice.length(); i++) {
    slice[i] = from++;
  }
}

TEST(SliceTest, Streams) {
  uint8_t buffer[30];
  Slice slice1(buffer, 10);
  Slice slice2(buffer + 10, 20);

  fill(slice1, 40);
  fill(slice2, 50);

  std::ostringstream oss;
  oss << slice1 << slice2;

  uint8_t buffer2[30];
  Slice slice3(buffer2, 10);
  Slice slice4(buffer2 + 10, 20);

  std::istringstream iss;

  iss.str(oss.str());

  iss >> slice3 >> slice4;

  EXPECT_EQ(slice1, slice3);
  EXPECT_EQ(slice2, slice4);
}

TEST(SliceTest, Copy) {
  uint8_t buffer1[20];
  uint8_t buffer2[20];

  Slice slice1(buffer1, 20);
  Slice slice2(buffer2, 20);

  fill(slice1, 0);
  fill(slice2, 30);

  slice1.copyTo(slice2);
  EXPECT_EQ(slice1, slice2);

  slice1(5,10).copyTo(slice2(10,15));
  EXPECT_EQ(slice1[5], slice2[10]);
  EXPECT_EQ(slice1[6], slice2[11]);
  EXPECT_EQ(slice1[7], slice2[12]);
  EXPECT_EQ(slice1[8], slice2[13]);
  EXPECT_EQ(slice1[9], slice2[14]);
}

TEST(SliceTest, CopyOverlap) {
  uint8_t buffer[20];
  Slice slice(buffer, 20);

  // forward
  fill(slice, 0);
  slice(0,10).copyTo(slice(5,15));
  EXPECT_EQ(slice[0], slice[5]);
  EXPECT_EQ(slice[1], slice[6]);
  EXPECT_EQ(slice[2], slice[7]);
  EXPECT_EQ(8, slice[13]);
  EXPECT_EQ(9, slice[14]);
  EXPECT_EQ(15, slice[15]);

  // backwards
  fill(slice, 0);
  slice(10).copyTo(slice(5,15));
  EXPECT_EQ(10, slice[5]);
  EXPECT_EQ(11, slice[6]);
  EXPECT_EQ(12, slice[7]);
  EXPECT_EQ(18, slice[13]);
  EXPECT_EQ(19, slice[14]);
  EXPECT_EQ(15, slice[15]);
}


TEST(SliceTest, ConstSliceFromSlice) {
  uint8_t buffer[20];
  Slice slice(buffer, 20);
  slice[0] = 'a';
  ASSERT_EQ('a', slice[0]);

  ConstSlice constSlice(slice);
  slice[0] = 'x';
  ASSERT_EQ('x', slice[0]);
  ASSERT_EQ('x', constSlice[0]);
}

TEST(SliceTest, VectorBackedSlice) {
  std::vector<uint8_t> vector(20);
  vector[0] = 'x';
  vector[1] = 'y';
  Slice slice(vector);
  ConstSlice constSlice(vector);
  ASSERT_EQ(20, slice.length());
  ASSERT_EQ('x', slice[0]);
  ASSERT_EQ('y', slice[1]);
  ASSERT_EQ('y', constSlice[1]);
  slice[1] = 'a';
  ASSERT_EQ('a', slice[1]);
  ASSERT_EQ('a', constSlice[1]);
  ASSERT_EQ('a', vector[1]);
}

TEST(SliceTest, ConstVectorBackedSlice) {
  const std::vector<uint8_t> vector = {'d','a','t','a'};
  ConstSlice slice(vector);
  ConstSlice constSlice(vector);
  ASSERT_EQ(4, slice.length());
  ASSERT_EQ('d', slice[0]);
  ASSERT_EQ('a', slice[1]);
  ASSERT_EQ('a', constSlice[1]);
}

}}
