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

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.Arrays;

import com.facebook.crypto.cipher.NativeGCMCipher;
import com.facebook.crypto.keychain.KeyChain;
import com.facebook.crypto.util.NativeCryptoLibrary;
import com.facebook.crypto.util.SystemNativeCryptoLibrary;

import android.annotation.TargetApi;
import android.os.Build;
import android.test.InstrumentationTestCase;
import android.util.Base64;

@TargetApi(Build.VERSION_CODES.GINGERBREAD)
public class NativeGCMCipherOutputStreamTest extends InstrumentationTestCase {
  private Crypto mCrypto;
  private NativeCryptoLibrary mNativeCryptoLibrary;
  private byte[] mData;
  private byte[] mIV;
  private byte[] mKey;
  private ByteArrayOutputStream mCipherOutputStream;

  protected void setUp() throws Exception {
    super.setUp();
    mNativeCryptoLibrary = new SystemNativeCryptoLibrary();
    KeyChain keyChain = new FakeKeyChain();
    mKey = keyChain.getCipherKey();
    mIV = keyChain.getNewIV();
    mCrypto = new Crypto(keyChain, mNativeCryptoLibrary);
    mData = new byte[CryptoTestUtils.NUM_DATA_BYTES];
    mCipherOutputStream = new ByteArrayOutputStream();
  }

  public void testCompatibleWithBouncycastle() throws Exception {
    OutputStream outputStream = mCrypto.getCipherOutputStream(
        mCipherOutputStream,
        new Entity(CryptoTestUtils.ENTITY_NAME));
    outputStream.write(mData);
    outputStream.close();
    byte[] opensslEncrypted = mCipherOutputStream.toByteArray();

    BouncyCastleHelper.Result result = BouncyCastleHelper.bouncyCastleEncrypt(mData,
        mKey,
        mIV,
        new Entity(CryptoTestUtils.ENTITY_NAME));

    byte[] opensslTag = tag(opensslEncrypted);
    byte[] opensslCipherText = cipherText(opensslEncrypted);

    assertTrue(
        CryptoTestUtils.ENCRYPTED_DATA_DOES_NOT_MATCH,
        Arrays.equals(result.cipherText, opensslCipherText)
    );
    assertTrue(CryptoTestUtils.TAG_DOES_NOT_MATCH, Arrays.equals(result.tag, opensslTag));
  }

  public void testWriteData() throws Exception {
    OutputStream outputStream = mCrypto.getCipherOutputStream(
        mCipherOutputStream,
        new Entity(CryptoTestUtils.ENTITY_NAME));
    outputStream.write(mData);
    outputStream.close();
    byte[] encryptedData = cipherText(mCipherOutputStream.toByteArray());

    assertTrue(CryptoTestUtils.ENCRYPTED_DATA_NULL, encryptedData != null);
    assertTrue(CryptoTestUtils.ENCRYPTED_DATA_OF_DIFFERENT_LENGTH,
        encryptedData.length == mData.length);
    assertTrue(CryptoTestUtils.DATA_IS_NOT_ENCRYPTED, !Arrays.equals(mData, encryptedData));
  }

  public void testWriteDataUsingOffsets() throws Exception {
    OutputStream outputStream = mCrypto.getCipherOutputStream(
        mCipherOutputStream,
        new Entity(CryptoTestUtils.ENTITY_NAME));
    outputStream.write(mData, 0, mData.length / 2);
    outputStream.write(mData, mData.length / 2, mData.length / 2 + mData.length % 2);
    outputStream.close();
    byte[] encryptedData = cipherText(mCipherOutputStream.toByteArray());

    assertTrue(CryptoTestUtils.ENCRYPTED_DATA_NULL, encryptedData != null);
    assertTrue(CryptoTestUtils.ENCRYPTED_DATA_OF_DIFFERENT_LENGTH,
        encryptedData.length == mData.length);
    assertTrue(CryptoTestUtils.DATA_IS_NOT_ENCRYPTED, !Arrays.equals(mData, encryptedData));
  }

  public void testEncryptedDataIsExpected() throws Exception {
    String dataToEncrypt = "data to encrypt";
    String expectedEncryptedString = "69VhniqXP+xA0CcKJFx5";
    OutputStream outputStream = mCrypto.getCipherOutputStream(
        mCipherOutputStream,
        new Entity(CryptoTestUtils.ENTITY_NAME));
    outputStream.write(dataToEncrypt.getBytes("UTF-8"));
    outputStream.close();
    byte[] encryptedData = cipherText(mCipherOutputStream.toByteArray());

    String encryptedString = Base64.encodeToString(encryptedData, Base64.DEFAULT).trim();
    assertEquals(CryptoTestUtils.ENCRYPTED_DATA_IS_DIFFERENT,
        expectedEncryptedString,
        encryptedString);
  }

  public byte[] cipherText(byte[] cipheredData) {
    return Arrays.copyOfRange(cipheredData,
        NativeGCMCipher.IV_LENGTH,
        cipheredData.length - NativeGCMCipher.TAG_LENGTH);
  }

  public byte[] tag(byte[] cipheredData) {
    return Arrays.copyOfRange(cipheredData,
        cipheredData.length - NativeGCMCipher.TAG_LENGTH,
        cipheredData.length);
  }
}
