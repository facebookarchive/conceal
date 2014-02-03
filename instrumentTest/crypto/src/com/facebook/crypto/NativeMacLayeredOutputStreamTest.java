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
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Random;

import android.annotation.TargetApi;
import android.os.Build;
import android.test.InstrumentationTestCase;

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
    mNativeCryptoLibrary = new SystemNativeCryptoLibrary();
    FakeKeyChain keyChain = new FakeKeyChain();
    mKey = keyChain.getMacKey();
    mCrypto = new Crypto(keyChain, mNativeCryptoLibrary);

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
}
