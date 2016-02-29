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

import java.io.OutputStream;
import java.security.Security;
import java.util.Random;

import com.facebook.crypto.benchmarks.cipher.AESCipher;
import com.facebook.crypto.benchmarks.cipher.BouncyCastleGCMCipher;
import com.facebook.crypto.benchmarks.cipher.NativeGCMCipherHelper;
import com.facebook.crypto.benchmarks.mac.HMAC;
import com.facebook.crypto.benchmarks.mac.NativeMacHelper;
import com.facebook.crypto.benchmarks.mac.streams.MacLayeredOutputStream;

import com.google.caliper.Param;
import com.google.caliper.SimpleBenchmark;
import com.google.common.io.NullOutputStream;
import org.spongycastle.jce.provider.BouncyCastleProvider;

public class CipherWriteBenchmark extends SimpleBenchmark {

  private byte[] mData;
  private NullOutputStream mNullOutputStream;
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
    Random random = new Random();
    mData = new byte[size];
    random.nextBytes(mData);
    mNullOutputStream = new NullOutputStream();
    mHMAC = HMAC.getInstance();
    mNativeGCMCipherHelper = NativeGCMCipherHelper.getInstance();

    mAESCipher = AESCipher.getInstance();
    Security.addProvider(new BouncyCastleProvider());
    mBCGCMCipher = BouncyCastleGCMCipher.getInstance();
  }

  public void timeAESWithHMAC(int reps) throws Exception {
    for (int i = 0; i < reps; ++i) {
      Mac mac = mHMAC.getMac();
      MacLayeredOutputStream macOs = new MacLayeredOutputStream(mac, mNullOutputStream);
      OutputStream aes = mAESCipher.getOutputStream(macOs);
      aes.write(mData);
      aes.close();
      mac.doFinal();
    }
  }

  public void timeNativeGCM(int reps) throws Exception {
    byte[] buffer = new byte[1024];
    for (int i = 0; i < reps; ++i) {
      OutputStream output = mNativeGCMCipherHelper.getOutputStream(mNullOutputStream, buffer);
      output.write(mData);
      output.close();
    }
  }

  public void timeBouncycastleGCMCipher(int reps) throws Exception {
    for (int i = 0; i < reps; ++i) {
      OutputStream output =  mBCGCMCipher.getOutputStream(mNullOutputStream);
      output.write(mData);
      output.close();
    }
  }
}
