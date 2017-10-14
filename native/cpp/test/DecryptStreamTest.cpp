// Copyright 2004-present Facebook. All Rights Reserved.

#include <gtest/gtest.h>

#include <conceal/Buffer.h>
#include <conceal/CryptoConfig.h>
#include <conceal/CryptoException.h>
#include <conceal/Decrypt.h>
#include <conceal/DecryptStream.h>
#include <conceal/Encrypt.h>
#include <conceal/EncryptStream.h>
#include <conceal/Slice.h>
#include "SliceTestHelpers.h"

namespace facebook { namespace conceal {

TEST(DecryptStreamTest, SeekOff) {
  CryptoConfig config = CryptoConfig::CONFIG_256();
  Buffer key(config.keyLength);
  Buffer iv(config.ivLength);
  Buffer entity(10);
  Buffer data(100);
  fillRange(key);
  fillRange(iv);
  fillRange(entity);
  fillRange(data);
  Encrypt encrypt(config, key, iv, entity);
  std::ostringstream output{};
  EncryptStream stream{&output, std::move(encrypt), 60};
  stream << data;
  stream.flush();
  stream.end();

  std::string result = output.str();
  EXPECT_EQ(130, result.size());

  std::istringstream input{result};
  Decrypt decrypt(config, key, entity);
  DecryptStream destream{input.rdbuf(), std::move(decrypt), config};
  destream.start();

  Buffer prefix(15);
  destream >> prefix;
  EXPECT_EQ(data(0, 15), prefix);

  destream.seekg(20, std::ios_base::cur);
  Buffer nextPiece(15);
  destream >> nextPiece;
  EXPECT_EQ(data(35, 50), nextPiece);
}

TEST(DecryptStreamTest, Formats) {
  CryptoConfig config = CryptoConfig::CONFIG_256();
  Buffer key(config.keyLength);
  Buffer iv(config.ivLength);
  Buffer entity(10);
  fillRange(key);
  fillRange(iv);
  fillRange(entity);
  Encrypt encrypt(config, key, iv, entity);
  std::ostringstream output{};
  EncryptStream stream{&output, std::move(encrypt), 60};
  stream << 123 << "," << 456;
  stream.flush();
  stream.end();

  std::string result = output.str();

  std::istringstream input{result};
  Decrypt decrypt(config, key, entity);
  DecryptStream destream{input.rdbuf(), std::move(decrypt), config};
  destream.start();

  EXPECT_EQ(0, destream.tellg());

  int num1;
  destream >> num1;
  EXPECT_EQ(123, num1);
  EXPECT_EQ(3, destream.tellg());
  EXPECT_FALSE(destream.eof());

  char c;
  destream >> c;
  EXPECT_EQ(',', c);
  EXPECT_EQ(4, destream.tellg());

  int num2;
  destream >> num2;
  EXPECT_EQ(456, num2);
  EXPECT_TRUE(destream.eof());
  EXPECT_TRUE(destream.validTag());
}

/**
 * Same as DecryptTest but with streams
 */
void testDecryptStream(
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

  Buffer encrypted(2 + iv.length() + cipher.length() + tag.length());
  header.copyTo(encrypted(0, header.length()));
  cipher.copyTo(encrypted(header.length(), header.length() + cipher.length()));
  tag.copyTo(encrypted(encrypted.length() - tag.length(), encrypted.length()));
  std::istringstream encryptedStream{};
  std::string encryptedString(reinterpret_cast<char*>(&encrypted[0]), encrypted.length());
  encryptedStream.rdbuf()->str(encryptedString);

  Buffer plain(expectedInput.length());
  CryptoConfig config = CryptoConfig::CONFIG_256();
  Decrypt decrypt(config, key, entity);
  DecryptStream decryptStream{encryptedStream.rdbuf(), std::move(decrypt), config};

  EXPECT_EQ(true, decryptStream.start());
  char data[chunkSize];
  int pos = 0;
  while (decryptStream && !decryptStream.eof()) {
    EXPECT_EQ(pos, decryptStream.tellg());
    decryptStream.read(data, chunkSize);
    int count = decryptStream.gcount();
    Slice(reinterpret_cast<uint8_t*>(data), count).copyTo(plain(pos, pos+count));
    pos += count;
  }
  bool tagWasOk = decryptStream.validTag();

  // all read and decrypted
  EXPECT_EQ(expectedInput, plain);
  // tag should match iif tagHex was provided
  EXPECT_EQ(tagHex != nullptr, tagWasOk);
}

const int MAX_CHUNK = 128;

void testDecryptStream(
    const char* keyHex,
    const char* ivHex,
    const char* entityHex,
    const char* expectedInputHex,
    const char* cipherHex,
    const char* tagHex) {

  SCOPED_TRACE(testing::Message() << "Decrypting with (" << keyHex << ")");

  for (int chunkSize = 10; chunkSize < MAX_CHUNK; chunkSize++) {
    testDecryptStream(keyHex, ivHex, entityHex, expectedInputHex, cipherHex, tagHex, chunkSize);
  }
}

TEST(DecryptStreamTest, Decrypt256_61bytes) {
  // Page 29 (2.6.2)
  testDecryptStream(
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
      // tag (check will fail)
      nullptr);
}

TEST(DecryptStreamTest, Decrypt1) {
  testDecryptStream(
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

TEST(DecryptStreamTest, Decrypt2) {
  testDecryptStream(
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

}}
