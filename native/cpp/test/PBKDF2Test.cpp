// Copyright 2004-present Facebook. All Rights Reserved.

#include <gtest/gtest.h>

#include <conceal/Buffer.h>
#include <conceal/PBKDF2.h>
#include <conceal/Slice.h>

#include "SliceTestHelpers.h"

namespace facebook { namespace conceal {

void testOneCase(
    const char* passwordAscii,
    const char* saltAscii,
    int iterations,
    int keyLength,
    const char* hexResult) {

  ConstSlice password(reinterpret_cast<const uint8_t*>(passwordAscii), strlen(passwordAscii));
  ConstSlice salt(reinterpret_cast<const uint8_t*>(saltAscii), strlen(saltAscii));
  Buffer expectedResult = hex2Buffer(hexResult);
  PBKDF2 p{};
  p.setPassword(password);
  p.setSalt(salt);
  p.setIterations(iterations);
  p.setKeyLengthInBytes(keyLength);
  ConstSlice result = p.generate();

  ASSERT_EQ((ConstSlice) expectedResult, result);
}

TEST(PBKDF2Test, TestVectors) {
  testOneCase(
      "password",
      "salt",
      1,
      32,
      "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
  testOneCase(
      "password",
      "salt",
      2,
      32,
      "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
  testOneCase(
      "password",
      "salt",
      4096,
      32,
      "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
  testOneCase(
      "passwordPASSWORDpassword",
      "saltSALTsaltSALTsaltSALTsaltSALTsalt",
      4096,
      40,
      "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9");
}

}}
