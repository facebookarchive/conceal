/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto.benchmarks;

import javax.crypto.Mac;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.Random;

import com.facebook.crypto.benchmarks.cipher.AESCipher;
import com.facebook.crypto.benchmarks.cipher.BaseCipher;
import com.facebook.crypto.benchmarks.cipher.BouncyCastleGCMCipher;
import com.facebook.crypto.benchmarks.cipher.NativeGCMCipherHelper;
import com.facebook.crypto.benchmarks.mac.HMAC;
import com.facebook.crypto.benchmarks.mac.NativeMacHelper;
import com.facebook.crypto.benchmarks.mac.streams.MacLayeredInputStream;

import com.google.caliper.Param;
import com.google.caliper.SimpleBenchmark;
import com.google.common.io.NullOutputStream;
import org.spongycastle.jce.provider.BouncyCastleProvider;

public class CipherReadBenchmark extends SimpleBenchmark {

  private byte[] mData;

  private byte[] mReadBuffer;

  private byte[] mNativeGCMCipheredData;
  private byte[] mBCGCMCipheredData;
  private byte[] mAESCipherText;

  private HMAC mHMAC;
  private NativeGCMCipherHelper mNativeGCMCipherHelper;

  // This field is purposely here so that we can get a
  // reference to NativeMac which is necessary for
  // library initialization.
  private NativeMacHelper mNativeMacHelper;

  private AESCipher mAESCipher;
  private BouncyCastleGCMCipher mBCGCMCipher;

  @Param({"102400"})
  int size;

  @Override
  public void setUp() throws Exception {
    // Initialize the buffers
    Random random = new Random();
    mData = new byte[size];
    random.nextBytes(mData);
    mReadBuffer = new byte[1024];

    // Initialize the ciphers and Macs.
    mHMAC = HMAC.getInstance();
    mNativeGCMCipherHelper = NativeGCMCipherHelper.getInstance();
    mAESCipher = AESCipher.getInstance();
    Security.addProvider(new BouncyCastleProvider());
    mBCGCMCipher = BouncyCastleGCMCipher.getInstance();

    // Initialize the ciphered outputs.
    mNativeGCMCipheredData = generateCipherText(mNativeGCMCipherHelper);
    mBCGCMCipheredData = generateCipherText(mBCGCMCipher);
    mAESCipherText = generateCipherText(mAESCipher);
  }

  private byte[] generateCipherText(BaseCipher cipher) throws Exception {
    ByteArrayOutputStream cipherText = new ByteArrayOutputStream();
    OutputStream out = cipher.getOutputStream(cipherText);
    out.write(mData);
    out.close();
    return cipherText.toByteArray();
  }

  private byte[] generateCipherText(NativeGCMCipherHelper gcmHelper)
      throws Exception {
    ByteArrayOutputStream cipherText = new ByteArrayOutputStream();
    OutputStream out = gcmHelper.getOutputStream(cipherText, new byte[1024]);
    out.write(mData);
    out.close();
    return cipherText.toByteArray();
  }

  public void timeBouncyCastleGCMRead(int reps) throws Exception {
    for (int i = 0; i < reps; ++i) {
      ByteArrayInputStream cipheredInput = new ByteArrayInputStream(mBCGCMCipheredData);
      InputStream input = mBCGCMCipher.getInputStream(cipheredInput);
      readFully(input, new NullOutputStream());
      // Not closing the bouncy castle stream on purpose because of a bug in
      // bouncycastle.
      //input.close();
    }
  }

  public void timeNativeGCMRead(int reps) throws Exception {
    for (int i = 0; i < reps; ++i) {
      ByteArrayInputStream cipheredInput = new ByteArrayInputStream(mNativeGCMCipheredData);
      InputStream input = mNativeGCMCipherHelper.getInputStream(cipheredInput);
      readFully(input, new NullOutputStream());
      input.close();
    }
  }

  public void timeAESWithHmacRead(int reps) throws Exception {
    for (int i = 0; i < reps; ++i) {
      ByteArrayInputStream cipheredInput = new ByteArrayInputStream(mAESCipherText);
      Mac mac = mHMAC.getMac();
      InputStream macStream = new MacLayeredInputStream(mac, cipheredInput);
      InputStream input = mAESCipher.getInputStream(macStream);
      readFully(input, new NullOutputStream());
      mac.doFinal();
      input.close();
    }
  }

  private void readFully(InputStream inputStream, OutputStream out) throws Exception {
    int read;
    while ((read = inputStream.read(mReadBuffer)) != -1) {
      out.write(mReadBuffer, 0, read);
    }
  }
}
