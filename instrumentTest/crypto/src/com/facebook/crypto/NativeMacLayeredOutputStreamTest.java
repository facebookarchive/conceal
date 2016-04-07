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
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Random;

import android.annotation.TargetApi;
import android.os.Build;
import android.test.InstrumentationTestCase;

import com.facebook.android.crypto.keychain.AndroidConceal;
import com.facebook.crypto.util.NativeCryptoLibrary;
import com.facebook.crypto.util.SystemNativeCryptoLibrary;

import com.google.common.base.Preconditions;

@TargetApi(Build.VERSION_CODES.GINGERBREAD)
public class NativeMacLayeredOutputStreamTest extends InstrumentationTestCase {

  private NativeCryptoLibrary mNativeCryptoLibrary;
  private Crypto mCrypto;
  private byte[] mKey;
  private byte[] mData;
  private Entity mEntity;

  public void setUp() {
    FakeKeyChain keyChain = new FakeKeyChain();
    mKey = keyChain.getMacKey();
    mCrypto = AndroidConceal.get().createCrypto128Bits(keyChain);

    Random random = new Random();
    mData = new byte[CryptoTestUtils.NUM_DATA_BYTES];
    random.nextBytes(mData);
    mEntity = new Entity(CryptoTestUtils.FAKE_ENTITY_NAME);
  }

  public void testMatchesWithJavaMac() throws Exception {
    Mac mac = Mac.getInstance("HmacSHA1");
    mac.init(new SecretKeySpec(mKey, "HmacSHA1"));
    byte[] aadData = CryptoSerializerHelper.computeBytesToAuthenticate(mEntity.getBytes(),
        VersionCodes.MAC_SERIALIZATION_VERSION,
        VersionCodes.MAC_ID);
    mac.update(aadData);
    byte[] javaMac = mac.doFinal(mData);

    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    OutputStream macStream = mCrypto.getMacOutputStream(
        bout,
        mEntity);
    macStream.write(mData);
    macStream.close();
    byte[] dataWithMac = bout.toByteArray();

    int macOffset = dataWithMac.length - javaMac.length;
    Preconditions.checkState(macOffset > 0);

    byte[] originalData = CryptoSerializerHelper.getOriginalDataFromMacData(dataWithMac, javaMac.length);
    byte[] nativeMac = CryptoSerializerHelper.getMacTag(dataWithMac, javaMac.length);
    assertTrue(Arrays.equals(mData, originalData));
    assertTrue(Arrays.equals(javaMac, nativeMac));
  }

  public void testAllBytesMacedIfPartialWrite() throws Exception {
    Mac mac = Mac.getInstance("HmacSHA1");
    mac.init(new SecretKeySpec(mKey, "HmacSHA1"));

    final int additionalDataSize = 200;
    final int numBytesToNotWrite = 100;
    byte[] additionalData = new byte[additionalDataSize];

    byte[] aadData = CryptoSerializerHelper.computeBytesToAuthenticate(mEntity.getBytes(),
      VersionCodes.MAC_SERIALIZATION_VERSION,
      VersionCodes.MAC_ID);

    mac.update(aadData);
    mac.update(mData);
    byte[] javaMac = mac.doFinal(additionalData);

    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    FailingOutputStream failingStream = new FailingOutputStream(bout);
    OutputStream macStream = mCrypto.getMacOutputStream(
      failingStream,
      mEntity);
    macStream.write(mData);

    failingStream.fail(numBytesToNotWrite);
    try {
      macStream.write(additionalData, 0, additionalDataSize);
      fail("Exception expected");
    } catch (IOException e) {
      // do nothing, this is expected.
    }

    failingStream.failOff();
    macStream.close();
    byte[] dataWithMac = bout.toByteArray();

    int macOffset = dataWithMac.length - javaMac.length;
    Preconditions.checkState(macOffset > 0);

    byte[] originalData = CryptoSerializerHelper.getOriginalDataFromMacData(dataWithMac, javaMac.length);
    byte[] nativeMac = CryptoSerializerHelper.getMacTag(dataWithMac, javaMac.length);

    assertTrue(Arrays.equals(mData, Arrays.copyOf(originalData, mData.length)));
    assertTrue(Arrays.equals(
      Arrays.copyOf(additionalData, additionalDataSize - numBytesToNotWrite),
      Arrays.copyOfRange(originalData, mData.length, originalData.length)));
    assertEquals(mData.length + additionalDataSize - numBytesToNotWrite, originalData.length);
    assertTrue(Arrays.equals(javaMac, nativeMac));
  }

  /**
   * An output stream that fails when you ask it to.
   */
  private class FailingOutputStream extends FilterOutputStream {

    private boolean mFail;
    private int mFailLeavingBytes;

    public FailingOutputStream(OutputStream out) {
      super(out);
    }

    /**
     * Fail, leaving num bytes not written.
     */
    public void fail(int num) {
      mFail = true;
      mFailLeavingBytes = num;
    }

    /**
     * Turn off the fail.
     */
    public void failOff() {
      mFail = false;
      mFailLeavingBytes = 0;
    }

    @Override
    public void write(byte[] data, int offset, int length) throws IOException {
      out.write(data, offset, length - mFailLeavingBytes);
      if (mFail) {
        throw new IOException();
      }
    }

    @Override
    public void write(int oneByte) throws IOException {
      out.write(oneByte);
      if (mFail) {
        throw new IOException();
      }
    }
  }

  public void testCloseMultipleTimes() throws Exception {
    OutputStream outputStream = mCrypto.getCipherOutputStream(
        new ByteArrayOutputStream(),
        mEntity);
    outputStream.close();
    try {
      outputStream.close();
      outputStream.close();
    } catch (Exception e) {
      fail("Multiple closes exception!");
    }
  }
}
