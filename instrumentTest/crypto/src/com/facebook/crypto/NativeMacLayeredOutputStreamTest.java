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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.util.Arrays;
import java.util.Random;

import android.annotation.TargetApi;
import android.os.Build;
import android.test.InstrumentationTestCase;

import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.mac.NativeMac;
import com.facebook.crypto.streams.NativeMacLayeredOutputStream;
import com.facebook.crypto.util.NativeCryptoLibrary;
import com.facebook.crypto.util.SystemNativeCryptoLibrary;

import com.google.common.base.Preconditions;

@TargetApi(Build.VERSION_CODES.GINGERBREAD)
public class NativeMacLayeredOutputStreamTest extends InstrumentationTestCase {

  private NativeCryptoLibrary mNativeCryptoLibrary;
  private byte[] mKey;
  private byte[] mData;

  public void setUp() {
    mNativeCryptoLibrary = new SystemNativeCryptoLibrary();
    Random random = new Random();
    mKey = new byte[NativeMac.KEY_LENGTH];
    random.nextBytes(mKey);

    mData = new byte[CryptoTestUtils.NUM_DATA_BYTES];
    random.nextBytes(mData);
  }

  public void testMatchesWithJavaMac() throws Exception {
    Mac mac = Mac.getInstance("HmacSHA1");
    mac.init(new SecretKeySpec(mKey, "HmacSHA1"));
    byte[] javaMac = mac.doFinal(mData);
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    NativeMacLayeredOutputStream macStream = new NativeMacLayeredOutputStream(
        getNativeMac(),
        bout);
    macStream.write(mData);
    macStream.close();
    byte[] dataWithMac = bout.toByteArray();
    int macOffset = dataWithMac.length - javaMac.length;
    Preconditions.checkState(macOffset > 0);

    byte[] originalData = Arrays.copyOfRange(dataWithMac, 0, macOffset);
    byte[] nativeMac = Arrays.copyOfRange(dataWithMac, macOffset, dataWithMac.length);
    assertTrue(Arrays.equals(mData, originalData));
    assertTrue(Arrays.equals(javaMac, nativeMac));
  }

  private NativeMac getNativeMac() throws CryptoInitializationException, IOException {
    NativeMac nativeMac = new NativeMac(mNativeCryptoLibrary);
    nativeMac.init(mKey, mKey.length);
    return nativeMac;
  }
}
