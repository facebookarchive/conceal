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
import java.util.Random;

import com.facebook.crypto.benchmarks.mac.HMAC;
import com.facebook.crypto.benchmarks.mac.NativeMacHelper;
import com.facebook.crypto.benchmarks.mac.streams.MacLayeredOutputStream;
import com.facebook.crypto.cipher.NativeGCMCipher;

import com.google.caliper.Param;
import com.google.caliper.SimpleBenchmark;
import com.google.common.io.NullOutputStream;

public class MacBenchmark extends SimpleBenchmark {

  private byte[] mData;

  private HMAC mHMAC;

  private NativeMacHelper mNativeMacHelper;

  // This field is purposely here so that we can get a
  // reference to NativeGCMCipher which is necessary for
  // library initialization.
  private NativeGCMCipher mNativeGCMCipher;

  @Param({"102400"})
  int size;

  @Override
  public void setUp() throws Exception {
    // Initialize the buffers
    Random random = new Random();
    mData = new byte[size];
    random.nextBytes(mData);

    mHMAC = HMAC.getInstance();
    mNativeMacHelper = NativeMacHelper.getInstance();
  }

  public void timeNativeMac(int reps) throws Exception {
    for (int i = 0; i < reps; ++i) {
      OutputStream output = mNativeMacHelper.getOutputStream(new NullOutputStream());
      output.write(mData);
      output.close();
    }
  }

  public void timeJavaHmac(int reps) throws Exception {
    for (int i = 0; i < reps; ++i) {
      Mac mac = mHMAC.getMac();
      OutputStream macOutput = new MacLayeredOutputStream(mac, new NullOutputStream());
      macOutput.write(mData);
      macOutput.close();
      mac.doFinal();
    }
  }
}
