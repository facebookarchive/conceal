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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Random;

import android.test.InstrumentationTestCase;

import com.facebook.crypto.keychain.KeyChain;
import com.facebook.crypto.util.NativeCryptoLibrary;
import com.facebook.crypto.util.SystemNativeCryptoLibrary;

import com.google.common.io.ByteStreams;

public class NativeMacLayeredInputStreamTest extends InstrumentationTestCase {

  private byte[] mData;
  private byte[] mDataWithMac;
  private NativeCryptoLibrary mNativeCryptoLibrary;
  private Crypto mCrypto;
  private Entity mEntity;
  private KeyChain mKeyChain;

  public void setUp() throws Exception {
    mNativeCryptoLibrary = new SystemNativeCryptoLibrary();
    mKeyChain = new FakeKeyChain();
    mCrypto = new Crypto(mKeyChain, mNativeCryptoLibrary);

    mData = new byte[CryptoTestUtils.NUM_DATA_BYTES];
    Random random = new Random();
    random.nextBytes(mData);

    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    mEntity = new Entity(CryptoTestUtils.ENTITY_NAME);
    OutputStream outputStream = mCrypto.getMacOutputStream(bout, mEntity);
    outputStream.write(mData);
    outputStream.close();
    mDataWithMac = bout.toByteArray();
  }

  public void testMacValidIfDataNotTamperedReadOneByteAtATime() throws Exception {
    InputStream macStream = mCrypto.getMacInputStream(
      new ByteArrayInputStream(mDataWithMac),
      mEntity);
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    int read;
    while ((read = macStream.read()) != -1) {
      output.write(read);
    }
    macStream.close();
    assertTrue(Arrays.equals(mData, output.toByteArray()));
  }

  public void testMacValidIfDataNotTampered() throws Exception {
    InputStream macStream = mCrypto.getMacInputStream(
        new ByteArrayInputStream(mDataWithMac),
        mEntity);
    byte[] output = ByteStreams.toByteArray(macStream);
    macStream.close();
    assertTrue(Arrays.equals(mData, output));
  }

  public void testMacNotValidIfDataTampered() throws Exception {
    byte[] tamperedData = mDataWithMac.clone();
    tamperedData[4] += 1;
    InputStream macStream = mCrypto.getMacInputStream(
        new ByteArrayInputStream(tamperedData),
        mEntity);
    try {
      ByteStreams.toByteArray(macStream);
    } catch (IOException e) {
      return;
    }
    fail("Mac should not be valid");
  }

  public void testMacNotValidIfMacTampered() throws Exception {
    byte[] tamperedData = mDataWithMac.clone();
    tamperedData[tamperedData.length - 1] += 1;
    InputStream macStream = mCrypto.getMacInputStream(
        new ByteArrayInputStream(tamperedData),
        mEntity);
    try {
      ByteStreams.toByteArray(macStream);
    } catch (IOException e) {
      return;
    }
    fail("Mac should not be valid");
  }

  public void testMacNotValidIfEntityDifferent() throws Exception {
    Entity fakeEntity = new Entity(CryptoTestUtils.FAKE_ENTITY_NAME);
    InputStream macStream = mCrypto.getMacInputStream(
        new ByteArrayInputStream(mDataWithMac),
        fakeEntity);
    try {
      ByteStreams.toByteArray(macStream);
    } catch (IOException e) {
      return;
    }
    fail("Mac should not be valid");
  }

  public void testThrowsOnCloseIfAllDataNotRead() throws Exception {
    InputStream macStream = mCrypto.getMacInputStream(
        new ByteArrayInputStream(mDataWithMac),
        mEntity);
    byte[] plainData = new byte[mDataWithMac.length - 200];
    macStream.read(plainData);
    try {
      macStream.close();
    } catch (IOException e) {
      return;
    }
    fail("Mac should not be valid");
  }

  public void testCompatibleWithJavaMac() throws Exception {
    Mac mac = Mac.getInstance("HmacSHA1");
    mac.init(new SecretKeySpec(mKeyChain.getMacKey(), "HmacSHA1"));
    byte[] entityBytes = mEntity.getBytes();
    byte[] aadBytes = CryptoSerializerHelper.computeBytesToAuthenticate(entityBytes,
        VersionCodes.MAC_SERIALIZATION_VERSION,
        VersionCodes.MAC_ID);

    mac.update(aadBytes);
    byte[] macBytes = mac.doFinal(mData);

    byte[] dataWithMac = CryptoSerializerHelper.createMacData(mData, macBytes);
    InputStream macStream = mCrypto.getMacInputStream(
        new ByteArrayInputStream(dataWithMac),
        mEntity);
    ByteStreams.toByteArray(macStream);
  }

  public void testCloseMultipleTimes() throws Exception {
    InputStream inputStream = mCrypto.getMacInputStream(
        new ByteArrayInputStream(mDataWithMac),
        mEntity);
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
