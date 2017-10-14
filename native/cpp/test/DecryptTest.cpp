// Copyright 2004-present Facebook. All Rights Reserved.

#include <gtest/gtest.h>

#include <conceal/Buffer.h>
#include <conceal/CryptoConfig.h>
#include <conceal/CryptoException.h>
#include <conceal/Decrypt.h>
#include <conceal/Slice.h>
#include "SliceTestHelpers.h"

namespace facebook { namespace conceal {

/**
 * The decryption examples are extracted from:
 * http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf
 * Except the tag, as here the tag is calculated based also on the format bytes and cannot
 * be changed to fit the example.
 *
 * Each test calls testDecrypt with a given data.
 * testDecrypt tries decryption using all possible chunk sizes between 1 and MAX_CHUNK.
 * That verifies that regardless of the chunk size used the output is correct and always
 * the same.
 *
 * This makes easier to test other components based on basic Decrypt (as JNI).
 * They only need to test with one chunk size or the whole size
 * (unless chunk size affects the other component in some relevant way).
 */

void testDecrypt(
    const char* keyHex,
    const char* ivHex,
    const char* entityHex,
    const char* expectedInputHex,
    const char* cipherHex,
    const char* tagHex,
    int chunkSize) {

  SCOPED_TRACE(testing::Message() << "Chunk size = " << chunkSize);

  Buffer key = hex2Buffer(keyHex);
  Buffer iv = hex2Buffer(ivHex);
  Buffer entity = hex2Buffer(entityHex);
  Buffer cipher = hex2Buffer(cipherHex);
  Buffer expectedInput = hex2Buffer(expectedInputHex);
  Buffer tag = tagHex ? hex2Buffer(tagHex) : Buffer(16);

  Buffer header(iv.length() + 2);
  header[0] = 1;
  header[1] = CryptoConfig::CONFIG_256().id;
  iv.copyTo(header(2));

  Buffer plain(expectedInput.length());
  Decrypt decrypt(CryptoConfig::CONFIG_256(), key, entity);
  decrypt.start(header);
  // offset is based on plain (no headers included)
  for (int offset = 0; offset < plain.length(); offset += chunkSize) {
    int end = offset + chunkSize;
    if (end > plain.length()) {
      end = plain.length();
    }
    decrypt.read(cipher(offset, end), plain(offset, end));
  }
  EXPECT_EQ(expectedInput, plain);
  bool verified = decrypt.end(tag);
  if (tagHex) {
    ASSERT_TRUE(verified) << "Tag doesn't verify";
  }
}

const int MAX_CHUNK = 128;

void testDecrypt(
    const char* keyHex,
    const char* ivHex,
    const char* entityHex,
    const char* expectedInputHex,
    const char* cipherHex,
    const char* tagHex) {

  SCOPED_TRACE(testing::Message() << "Decrypting with (" << keyHex << ")");

  for (int chunkSize = 1; chunkSize < MAX_CHUNK; chunkSize++) {
    testDecrypt(keyHex, ivHex, entityHex, expectedInputHex, cipherHex, tagHex, chunkSize);
  }

}

TEST(DecryptTest, MoveConstructor) {
  CryptoConfig config = CryptoConfig::CONFIG_256();
  Buffer key(config.keyLength);
  Buffer entity(10);
  Decrypt decrypt(config, key, entity);
  Decrypt other(std::move(decrypt));
}

TEST(DecryptTest, MoveAssignment) {
  CryptoConfig config = CryptoConfig::CONFIG_256();
  Buffer key(config.keyLength);
  Buffer entity(10);
  Decrypt decrypt(config, key, entity);
  Decrypt other = std::move(decrypt);
}

TEST(DecryptTest, Decrypt256_61bytes) {
  // Page 29 (2.6.2)
  testDecrypt(
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
  "D4",
  // tag (don't check: our AAD includes version bytes)
  nullptr);
}

TEST(DecryptTest, Decrypt1) {
  testDecrypt(
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
      "c5f61e6393ba7a0abcc9f662898015ad",
      // tag
      "51836a0acfe765db1f088df340d4e96a");
 }

TEST(DecryptTest, Decrypt2) {
  testDecrypt(
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
      "c5f61e6393ba7a0abcc9f662",
      // tag
      "0a88c9a39be67ba5e996ee597b5e4a49");
}

TEST(DecryptTest, StateExceptionNoStart1) {
  CryptoConfig config = CryptoConfig::CONFIG_256();
  Buffer key(config.keyLength);
  Buffer entity(10);
  Decrypt decrypt(config, key, entity);

  Buffer src(10), target(10);
  ASSERT_THROW(decrypt.read(src, target), CryptoException);
}

TEST(DecryptTest, StateExceptionNoStart2) {
  CryptoConfig config = CryptoConfig::CONFIG_256();
  Buffer key(config.keyLength);
  Buffer entity(10);
  Buffer tag(config.tagLength);

  Decrypt decrypt(config, key, entity);
  ASSERT_THROW(decrypt.end(tag), CryptoException);
}

TEST(DecryptTest, StateExceptionDoubleStart) {
  CryptoConfig config = CryptoConfig::CONFIG_256();
  Buffer key(config.keyLength);
  Buffer entity(10);
  Buffer header(2 + config.ivLength);
  header[0] = 1;
  header[1] = config.id;

  Decrypt decrypt(config, key, entity);
  decrypt.start(header);
  ASSERT_THROW(decrypt.start(header), CryptoException);
}

TEST(DecryptTest, StateExceptionDoubleEnd) {
  CryptoConfig config = CryptoConfig::CONFIG_256();
  Buffer key(config.keyLength);
  Buffer entity(10);
  Buffer header(2 + config.ivLength);
  header[0] = 1;
  header[1] = config.id;
  Buffer tag(config.tagLength);

  Decrypt decrypt(config, key, entity);
  decrypt.start(header);
  decrypt.end(tag);
  ASSERT_THROW(decrypt.end(tag), CryptoException);
}

}}
