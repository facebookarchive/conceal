// Copyright 2004-present Facebook. All Rights Reserved.

#include <gtest/gtest.h>

#include <conceal/Buffer.h>
#include <conceal/Cipher.h>
#include <conceal/Decrypt.h>
#include <conceal/Encrypt.h>
#include <conceal/KeyChain.h>
#include <conceal/Slice.h>

#include "SliceTestHelpers.h"
#include "TestKeyChain.h"

namespace facebook { namespace conceal {

/**
 * Test a Cipher object by encrypting some arbitrary data and decrypting it.
 * This checks the result data is the same. It also checks that the header
 * for the cipher text is correct.
 *
 * More testing could be nice, like testing that manually-created
 * Encrypt/Decrypt objects produce the same result... but Cipher implementation
 * is pretty simple and straight-forward.
 */
TEST(CipherTest, Crypto0) {
  CryptoConfig config = CryptoConfig::CONFIG_256();
  Buffer key(config.keyLength);
  Buffer iv(config.ivLength);

  fillRange(key);
  fillRange(iv);

  TestKeyChain keyChain(key, iv);
  Cipher cipher(config, keyChain);

  Buffer entity(10);
  fillRange(entity);

  Buffer data(200);
  fillRange(data);
  Buffer result(2 + config.ivLength + data.length() + config.tagLength);

  Encrypt e = cipher.createEncrypt(entity);
  Slice header = e.start();
  header.copyTo(result(0, header.length()));

  int tailPosition = header.length() + data.length();
  e.write(data, result(header.length(), tailPosition));

  Slice tail = e.end();
  tail.copyTo(result(tailPosition));

  EXPECT_EQ(1, result[0]);
  EXPECT_EQ(2, result[1]);
  EXPECT_EQ(iv, result(2, 2 + config.ivLength));

  Decrypt d = cipher.createDecrypt(entity);

  Buffer resultPlain(data.length());

  d.start(result(0, header.length()));
  d.read(result(header.length(), tailPosition), resultPlain);
  bool verified = d.end(result(tailPosition));

  EXPECT_TRUE(verified);
  EXPECT_EQ(data, resultPlain);
}

}}
