/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Random;

import com.facebook.crypto.cipher.NativeGCMCipher;
import com.facebook.crypto.cipher.NativeGCMCipherException;
import com.facebook.crypto.keychain.KeyChain;
import com.facebook.crypto.util.NativeCryptoLibrary;
import com.facebook.crypto.util.SystemNativeCryptoLibrary;

import android.annotation.TargetApi;
import android.os.Build;
import android.test.InstrumentationTestCase;

import com.google.common.io.ByteStreams;
import com.google.common.io.Closeables;

@TargetApi(Build.VERSION_CODES.GINGERBREAD)
public class NativeGCMCipherInputStreamTest extends InstrumentationTestCase {

  private Crypto mCrypto;
  private NativeCryptoLibrary mNativeCryptoLibrary;
  private byte[] mData;

  private ByteArrayInputStream mCipherInputStream;
  private byte[] mCipheredData;
  private byte[] mIV;
  private byte[] mKey;

  protected void setUp() throws Exception {
    super.setUp();
    mNativeCryptoLibrary = new SystemNativeCryptoLibrary();
    KeyChain keyChain = new FakeKeyChain();
    mCrypto = new Crypto(keyChain, mNativeCryptoLibrary);
    mIV = keyChain.getNewIV();
    mKey = keyChain.getCipherKey();

    // Encrypt some data before each test.
    mData = new byte[CryptoTestUtils.NUM_DATA_BYTES];
    Random random = new Random();
    random.nextBytes(mData);

    ByteArrayOutputStream cipherOutputStream = new ByteArrayOutputStream();

    OutputStream outputStream = mCrypto.getCipherOutputStream(
        cipherOutputStream,
        new Entity(CryptoTestUtils.ENTITY_NAME));
    outputStream.write(mData);
    outputStream.close();

    mCipheredData = cipherOutputStream.toByteArray();
    mCipherInputStream = new ByteArrayInputStream(mCipheredData);
  }

  public void testDecryptionFailsOnIncorrectEntity() throws Exception {
    InputStream inputStream = null;
    try {
      inputStream = mCrypto.getCipherInputStream(
          mCipherInputStream,
          new Entity(CryptoTestUtils.FAKE_ENTITY_NAME)
      );

      // We expect an exception when all the bytes are read.
      try {
        ByteStreams.toByteArray(inputStream);
      } catch (IOException e) {
        return;
      }
      Closeables.closeQuietly(inputStream);
    } finally {
      Closeables.closeQuietly(inputStream);
    }
    fail(CryptoTestUtils.EXCEPTION_EXPECTED);
  }

  public void testDecryptionFailsOnIncorrectTag() throws Exception {
    byte[] fakeTag = new byte[NativeGCMCipher.TAG_LENGTH];
    Arrays.fill(fakeTag, (byte) CryptoTestUtils.KEY_BYTES);

    // Overwrite the tag bytes.
    System.arraycopy(fakeTag,
        0,
        mCipheredData,
        mCipheredData.length - NativeGCMCipher.TAG_LENGTH,
        NativeGCMCipher.TAG_LENGTH);

    InputStream inputStream = null;
    try {
      inputStream = mCrypto.getCipherInputStream(
          mCipherInputStream,
          new Entity(CryptoTestUtils.ENTITY_NAME)
      );
      ByteStreams.toByteArray(inputStream);
    } catch (IOException e) {
      return;
    } finally {
      Closeables.closeQuietly(inputStream);
    }
    fail(CryptoTestUtils.EXCEPTION_EXPECTED);
  }

  public void testDecryptionFailsOnIncorrectData() throws Exception {
    byte[] fakeData = new byte[CryptoTestUtils.NUM_DATA_BYTES];
    Arrays.fill(fakeData, (byte) CryptoTestUtils.KEY_BYTES);
    byte[] realTag = CryptoSerializerHelper.tag(mCipheredData);
    byte[] tamperedCipherData = CryptoSerializerHelper.createCipheredData(mIV,
        fakeData,
        realTag);

    ByteArrayInputStream fakeCipherInputStream = new ByteArrayInputStream(tamperedCipherData);
    InputStream inputStream = null;
    try {
      inputStream = mCrypto.getCipherInputStream(
          fakeCipherInputStream,
          new Entity(CryptoTestUtils.ENTITY_NAME)
      );

      // We expect an exception after reading all the bytes
      try {
        ByteStreams.toByteArray(inputStream);
      } catch (IOException e) {
        return;
      }
    } finally {
      Closeables.closeQuietly(inputStream);
    }
    fail(CryptoTestUtils.EXCEPTION_EXPECTED);
  }

  public void testDecryptValidData() throws Exception {
    InputStream inputStream = mCrypto.getCipherInputStream(
        mCipherInputStream,
        new Entity(CryptoTestUtils.ENTITY_NAME));
    byte[] decryptedData = ByteStreams.toByteArray(inputStream);
    inputStream.close();
    assertTrue(CryptoTestUtils.DECRYPTED_DATA_IS_DIFFERENT, Arrays.equals(mData, decryptedData));
  }

  public void testDecryptAndSkipValidData() throws Exception {
    InputStream inputStream = mCrypto.getCipherInputStream(
        mCipherInputStream,
        new Entity(CryptoTestUtils.ENTITY_NAME));
    int partSize = CryptoTestUtils.NUM_DATA_BYTES / 4;
    byte[] firstPart = new byte[partSize];
    ByteStreams.readFully(inputStream, firstPart);
    long skipped = inputStream.skip(partSize);
    byte[] decryptedData = ByteStreams.toByteArray(inputStream);
    inputStream.close();
    assertTrue(
        CryptoTestUtils.DECRYPTED_DATA_IS_DIFFERENT,
        Arrays.equals(Arrays.copyOfRange(mData, 0, partSize), firstPart));
    assertEquals(skipped, partSize);
    assertTrue(
        CryptoTestUtils.DECRYPTED_DATA_IS_DIFFERENT,
        Arrays.equals(Arrays.copyOfRange(mData, partSize*2, mData.length), decryptedData));
  }

  public void testDecryptValidDataInSmallIncrements() throws Exception {
    InputStream inputStream = mCrypto.getCipherInputStream(
        mCipherInputStream,
        new Entity(CryptoTestUtils.ENTITY_NAME));

    ByteArrayOutputStream decryptedData = new ByteArrayOutputStream();
    byte[] buffer = new byte[NativeGCMCipher.TAG_LENGTH / 6];
    int read;
    while ((read = inputStream.read(buffer)) != -1) {
      assertTrue(read > 0);
      decryptedData.write(buffer, 0, read);
    }

    inputStream.close();
    assertTrue(CryptoTestUtils.DECRYPTED_DATA_IS_DIFFERENT,
        Arrays.equals(mData, decryptedData.toByteArray()));
  }

  public void testDecryptValidDataReadUsingOffsets() throws Exception {
    byte[] decryptedData = new byte[CryptoTestUtils.NUM_DATA_BYTES];
    InputStream inputStream = mCrypto.getCipherInputStream(
        mCipherInputStream,
        new Entity(CryptoTestUtils.ENTITY_NAME));

    int readSize = decryptedData.length / 2;
    ByteStreams.readFully(inputStream, decryptedData, 0, readSize);
    ByteStreams.readFully(inputStream, decryptedData, readSize, decryptedData.length - readSize);

    // read the remaining bytes.
    ByteStreams.toByteArray(inputStream);
    inputStream.close();
    assertTrue(CryptoTestUtils.DECRYPTED_DATA_IS_DIFFERENT, Arrays.equals(mData, decryptedData));
  }

  public void testThrowsOnCloseWhenAllDataNotRead() throws Exception {
    byte[] decryptedData = new byte[CryptoTestUtils.NUM_DATA_BYTES];
    InputStream inputStream = mCrypto.getCipherInputStream(
        mCipherInputStream,
        new Entity(CryptoTestUtils.ENTITY_NAME));

    int readSize = decryptedData.length / 2;
    ByteStreams.readFully(inputStream, decryptedData, 0, readSize);
    try {
      inputStream.close();
    } catch (NativeGCMCipherException e) {
      return;
    }
    fail(CryptoTestUtils.EXCEPTION_EXPECTED);
  }

  public void testCompatibleWithBouncyCastle() throws Exception {
    Entity entity = new Entity(CryptoTestUtils.ENTITY_NAME);
    byte[] aadData = CryptoSerializerHelper.computeBytesToAuthenticate(entity.getBytes(),
        VersionCodes.CIPHER_SERIALIZATION_VERSION,
        VersionCodes.CIPHER_ID);
    BouncyCastleHelper.Result result = BouncyCastleHelper.bouncyCastleEncrypt(mData,
        mKey,
        mIV,
        aadData);

    byte[] cipheredData = CryptoSerializerHelper.createCipheredData(mIV, result.cipherText, result.tag);

    InputStream inputStream = mCrypto.getCipherInputStream(
        new ByteArrayInputStream(cipheredData),
        new Entity(CryptoTestUtils.ENTITY_NAME));
    byte[] decryptedData = ByteStreams.toByteArray(inputStream);
    inputStream.close();
    assertTrue(CryptoTestUtils.DECRYPTED_DATA_IS_DIFFERENT, Arrays.equals(mData, decryptedData));
  }

  public void testCloseMultipleTimes() throws Exception {
    InputStream inputStream = mCrypto.getCipherInputStream(
        mCipherInputStream,
        new Entity(CryptoTestUtils.ENTITY_NAME));
    ByteStreams.toByteArray(inputStream);
    inputStream.close();
    try {
      inputStream.close();
      inputStream.close();
    } catch (Exception e) {
      fail("Multiple closes exception!");
    }
  }
}
