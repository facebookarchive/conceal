// Copyright 2004-present Facebook. All Rights Reserved.

#include <gtest/gtest.h>

#include <conceal/CryptoConfig.h>
#include <conceal/CryptoException.h>
#include <conceal/Encrypt.h>
#include <conceal/Slice.h>
#include "SliceTestHelpers.h"

namespace facebook { namespace conceal {

/**
 * The encryption examples are extracted from:
 * http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf
 *
 * Each example calls testEncrypt
 * which calls testEncryptSize for each size between 1 and 128.
 * That way we know that regardless of the chunk size that is fed to the encrypter
 * all work well and produce the same result.
 *
 * Therefore if you want to test other components (like from JNI), you just need
 * to test one chunk size (unless chunk size is somehow related to JNI, which shouldn't).
 */

const int MAX_CHUNK_SIZE = 128;

void testEncryptSize(
    const char* keyHex,
    const char* ivHex,
    const char* entityHex,
    const char* inputHex,
    const char* expectedCipherHex,
    int chunkSize) {

  SCOPED_TRACE(testing::Message() << "chunkSize = " << chunkSize);

  Buffer key = hex2Buffer(keyHex);
  Buffer input = hex2Buffer(inputHex);
  Buffer iv = hex2Buffer(ivHex);
  Buffer entity = hex2Buffer(entityHex);
  Buffer expectedCipher = hex2Buffer(expectedCipherHex);

  Buffer result(input.length() + 30);
  Encrypt c(CryptoConfig::CONFIG_256(), key, iv, entity);

  Slice header = c.start();
  header.copyTo(result(0, 2+12));

  // call the write method in chunkSize pieces
  for (int offset = 0; offset < input.length(); offset += chunkSize) {
    int end = offset + chunkSize;
    if (end > input.length()) {
      end = input.length();
    }
    // as we already have the whole space we just need to slice it
    Slice src = input(offset, end);
    Slice target = result(offset + 14, end + 14);
    c.write(src, target);
  }

  Slice tail = c.end();
  tail.copyTo(result(2+12+input.length()));

  EXPECT_EQ(1, result[0]);
  EXPECT_EQ(2, result[1]);
  EXPECT_EQ(iv, result(2, 2+12));
  EXPECT_EQ(expectedCipher, result(14, 14+expectedCipher.length()));
}


void testEncrypt(
    const char* keyHex,
    const char* ivHex,
    const char* entityHex,
    const char* inputHex,
    const char* expectedCipherHex) {

  SCOPED_TRACE(testing::Message() << "Encrypt(key = " << keyHex << ")");

  for (int chunkSize = 1; chunkSize < MAX_CHUNK_SIZE; chunkSize++) {
    testEncryptSize(keyHex, ivHex, entityHex, inputHex, expectedCipherHex, chunkSize);
  }
}

// uses the encrypt passed by param with the same data
Buffer encryptWith(Encrypt& encrypt) {
  Buffer plain(50);
  Buffer result(plain.length() + 14 + 16);
  fillRange(plain);
  encrypt.start().copyTo(result(0, 14));
  encrypt.write(plain, result(14, 14 + plain.length()));
  encrypt.end().copyTo(result(14 + plain.length()));
  return result;
}

TEST(EncryptTest, MoveConstructor) {
  CryptoConfig config = CryptoConfig::CONFIG_256();
  Buffer key(config.keyLength);
  Buffer iv(config.ivLength);
  Buffer entity(10);
  fillRange(key);
  fillRange(iv);
  fillRange(entity);

  Encrypt first(config, key, iv, entity);
  Buffer firstResult = encryptWith(first);

  Encrypt encrypt(config, key, iv, entity);
  Encrypt other(std::move(encrypt));
  Buffer movedResult = encryptWith(other);

  EXPECT_EQ(firstResult, movedResult);
}

TEST(EncryptTest, MoveAssignment) {
  CryptoConfig config = CryptoConfig::CONFIG_256();
  Buffer key(config.keyLength);
  Buffer iv(config.ivLength);
  Buffer entity(10);
  fillRange(key);
  fillRange(iv);
  fillRange(entity);

  Encrypt first(config, key, iv, entity);
  Buffer firstResult = encryptWith(first);

  Encrypt encrypt(config, key, iv, entity);
  Encrypt other = std::move(encrypt);
  Buffer movedResult = encryptWith(other);

  EXPECT_EQ(firstResult, movedResult);
}

TEST(EncryptTest, Crypto0) {
  // Page 10 (2.2.2)
  testEncrypt(
      // key
      "E3C08A8F06C6E3AD95A70557B23F7548"
      "3CE33021A9C72B7025666204C69C0B72",
      // iv
      "12153524C0895E81B2C28465",
      // entity
      "D609B1F056637A0D46DF998D88E52E00"
      "B2C2846512153524C0895E81",
      // input
      "08000F101112131415161718191A1B1C"
      "1D1E1F202122232425262728292A2B2C"
      "2D2E2F303132333435363738393A0002",
      // cipher
      "E2006EB42F5277022D9B19925BC419D7"
      "A592666C925FE2EF718EB4E308EFEAA7"
      "C5273B394118860A5BE2A97F56AB7836");
}

TEST(EncryptTest, Crypto256_61bytes) {
  // Page 29 (2.6.2)
  testEncrypt(
    // key
    "83C093B58DE7FFE1C0DA926AC43FB360"
    "9AC1C80FEE1B624497EF942E2F79A823",
    // iv
    "7CFDE9F9E33724C68932D612",
    // entity
    "84C5D513D2AAF6E5BBD2727788E52F00"
    "8932D6127CFDE9F9E33724C6",
    // input
    "08000F101112131415161718191A1B1C"
    "1D1E1F202122232425262728292A2B2C"
    "2D2E2F303132333435363738393A3B00"
    "06",
    // cipher
    "110222FF8050CBECE66A813AD09A73ED"
    "7A9A089C106B959389168ED6E8698EA9"
    "02EB1277DBEC2E68E473155A15A7DAEE"
    "D4");
}

TEST(EncryptTest, Crypto1) {
  testEncrypt(
      // key
      "feffe9928665731c6d6a8f9467308308"
      "feffe9928665731c6d6a8f9467308308",
      // iv
      "cafebabefacedbaddecaf888",
      // entity
      "1234567890abcdef",
      // input
      "d9313225f88406e5a55909c5aff5269a"
      "86a7a9531534f7da2e4c303d8a318a72"
      "1c3c0c95956809532fcf0e2449a6b525"
      "b16aedf5aa0de657ba637b391aafd255",
      // cipher
      "522dc1f099567d07f47f37a32a84427d"
      "643a8cdcbfe5c0c97598a2bd2555d1aa"
      "8cb08e48590dbb3da7b08b1056828838"
      "c5f61e6393ba7a0abcc9f662898015ad");
}

TEST(EncryptTest, Crypto2) {
  testEncrypt(
      // key
      "feffe9928665731c6d6a8f9467308308"
      "feffe9928665731c6d6a8f9467308308",
      // iv
      "cafebabefacedbaddecaf888",
      // entity
      "1234567890abcdef",
      // plain text
      "d9313225f88406e5a55909c5aff5269a"
      "86a7a9531534f7da2e4c303d8a318a72"
      "1c3c0c95956809532fcf0e2449a6b525"
      "b16aedf5aa0de657ba637b39",
      // cipher text
      "522dc1f099567d07f47f37a32a84427d"
      "643a8cdcbfe5c0c97598a2bd2555d1aa"
      "8cb08e48590dbb3da7b08b1056828838"
      "c5f61e6393ba7a0abcc9f662");
}

TEST(EncryptTest, StateExceptionNoStart1) {
  CryptoConfig config = CryptoConfig::CONFIG_256();
  Buffer key(config.keyLength);
  Buffer iv(config.ivLength);
  Buffer entity(10);
  Buffer src(10), target(10);
  Encrypt e(config, key, iv, entity);
  ASSERT_THROW(e.write(src, target), CryptoException);
}

TEST(EncryptTest, StateExceptionNoStart2) {
  CryptoConfig config = CryptoConfig::CONFIG_256();
  Buffer key(config.keyLength);
  Buffer iv(config.ivLength);
  Buffer entity(10);
  Encrypt e(config, key, iv, entity);
  ASSERT_THROW(e.end(), CryptoException);
}

TEST(EncryptTest, StateExceptionDoubleStart) {
  CryptoConfig config = CryptoConfig::CONFIG_256();
  Buffer key(config.keyLength);
  Buffer iv(config.ivLength);
  Buffer entity(10);
  Encrypt e(config, key, iv, entity);
  e.start();
  ASSERT_THROW(e.start(), CryptoException);
}

TEST(EncryptTest, StateExceptionDoubleEnd) {
  CryptoConfig config = CryptoConfig::CONFIG_256();
  Buffer key(config.keyLength);
  Buffer iv(config.ivLength);
  Buffer entity(10);
  Encrypt e(config, key, iv, entity);
  e.start();
  e.end();
  ASSERT_THROW(e.end(), CryptoException);
}

}}
