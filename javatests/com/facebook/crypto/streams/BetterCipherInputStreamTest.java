/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto.streams;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import com.google.common.io.ByteStreams;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class BetterCipherInputStreamTest {

  private byte[] mData;
  private byte[] mCipheredData;
  private Key mKey;
  private AlgorithmParameterSpec mIV;

  private static final String CIPHER_ALG = "AES/CTR/NoPadding";

  @Before
  public void setUp() throws Exception {
    mData = new byte[1024 * 1024];
    mCipheredData = new byte[mData.length];
    byte[] iv = new byte[16];
    byte[] key = new byte[16];
    mKey = new SecretKeySpec(key, "AES");
    Cipher cipher = Cipher.getInstance(CIPHER_ALG);
    mIV = new IvParameterSpec(iv);
    cipher.init(Cipher.ENCRYPT_MODE, mKey, mIV);
    mCipheredData = cipher.update(mData, 0, mData.length);
    cipher.doFinal();
  }

  @Test
  public void testDecryptsCorrectly() throws Exception {
    ByteArrayInputStream input = new ByteArrayInputStream(mCipheredData);
    BetterCipherInputStream cipherStream = new BetterCipherInputStream(input, getDecrypt());
    byte[] decryptedBytes = ByteStreams.toByteArray(cipherStream);
    Assert.assertArrayEquals(decryptedBytes, mData);
  }

  private Cipher getDecrypt() throws Exception {
    Cipher cipher = Cipher.getInstance(CIPHER_ALG);
    cipher.init(Cipher.DECRYPT_MODE, mKey, mIV);
    return cipher;
  }
}
