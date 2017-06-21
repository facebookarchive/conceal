// Copyright 2004-present Facebook. All Rights Reserved.

#include <gtest/gtest.h>

// Some tests I want to do on C++ i/o streams
#include <ostream>
#include <conceal/Encrypt.h>
#include <conceal/EncryptStream.h>

#include "SliceTestHelpers.h"

namespace facebook { namespace conceal {

void testEncrypt(Slice key, Slice iv, Slice entity, Slice input, Slice cipher, int chunk) {
  SCOPED_TRACE(testing::Message() << "Encrypt(chunk = " << chunk << ")");

  std::stringbuf target(std::ios_base::out);
  std::ostream targetStream(&target);

  Encrypt encrypt(CryptoConfig::CONFIG_256(), key, iv, entity);
  EncryptStream stream(&targetStream, std::move(encrypt), 10);
  char* source = reinterpret_cast<char*>(&input[0]);
  int remaining = input.length();
  while (remaining > 0) {
    chunk = std::min(chunk, remaining);
    stream.write(source, chunk);
    source += chunk;
    remaining -= chunk;
  }
  stream.flush();
  std::string resultBeforeEnd = target.str();
  stream.end();
  std::string result = target.str();

  EXPECT_EQ(cipher.length() + 14, resultBeforeEnd.size());
  EXPECT_EQ(cipher.length() + 14 + 16, result.size());
  // check format bytes
  EXPECT_EQ((uint8_t) 1, result[0]);
  EXPECT_EQ((uint8_t) 2, result[1]);
  // check IV
  for (int i=0; i<iv.length(); i++) {
    EXPECT_EQ(iv[i], (uint8_t) result[i+2]);
  }
  // check cipher
  for (int i=0; i<cipher.length(); i++) {
    EXPECT_EQ(cipher[i], (uint8_t) result[i+14]);
  }
}

TEST(StreamsTest, Encrypt1) {
  Buffer key = hex2Buffer(
      "E3C08A8F06C6E3AD95A70557B23F7548"
      "3CE33021A9C72B7025666204C69C0B72");
  Buffer iv = hex2Buffer(
      "12153524C0895E81B2C28465");
  Buffer entity = hex2Buffer(
      "D609B1F056637A0D46DF998D88E52E00"
      "B2C2846512153524C0895E81");
  Buffer input = hex2Buffer(
      "08000F101112131415161718191A1B1C"
      "1D1E1F202122232425262728292A2B2C"
      "2D2E2F303132333435363738393A0002");
  Buffer cipher = hex2Buffer(
      "E2006EB42F5277022D9B19925BC419D7"
      "A592666C925FE2EF718EB4E308EFEAA7"
      "C5273B394118860A5BE2A97F56AB7836");

  for (int i=1; i<input.length(); i++) {
    testEncrypt(key, iv, entity, input, cipher, i);
  }
}

}}
