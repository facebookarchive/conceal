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

import android.annotation.TargetApi;
import android.os.Build;
import android.test.InstrumentationTestCase;

import com.facebook.android.crypto.keychain.AndroidCryptoLibrary;
import com.facebook.crypto.keychain.KeyChain;
import com.facebook.soloader.SoLoader;

import junit.framework.Assert;

import java.io.IOException;
import java.util.Arrays;

import static com.facebook.crypto.CryptoTestUtils.fixedKeyChain;
import static com.facebook.crypto.CryptoTestUtils.toBytes;

/**
 * Checks that using Entity.create method works fine.
 */
@TargetApi(Build.VERSION_CODES.GINGERBREAD)
public class EntityFactoryTest extends InstrumentationTestCase {


    protected void setUp() throws Exception {
      SoLoader.init(this.getInstrumentation().getContext(), false);
    }

    public void testCases() throws Exception {
        // Test Case 15 - Page 39
        testCase(
                // key
                "feffe9928665731c6d6a8f9467308308" +
                "feffe9928665731c6d6a8f9467308308",
                // iv
                "cafebabefacedbaddecaf888",
                // plain text
                "d9313225f88406e5a55909c5aff5269a" +
                "86a7a9531534f7da2e4c303d8a318a72" +
                "1c3c0c95956809532fcf0e2449a6b525" +
                "b16aedf5aa0de657ba637b391aafd255",
                // entity id
                "anything");
        // Test Case 16 - Page 40
        testCase(
                // key
                "feffe9928665731c6d6a8f9467308308" +
                "feffe9928665731c6d6a8f9467308308",
                // iv
                "cafebabefacedbaddecaf888",
                // plain text
                "d9313225f88406e5a55909c5aff5269a" +
                "86a7a9531534f7da2e4c303d8a318a72" +
                "1c3c0c95956809532fcf0e2449a6b525" +
                "b16aedf5aa0de657ba637b39",
                // cipher text
                "whatever");
    }

    public void testCase(String key, String iv, String plain, String entityId) throws Exception {
        // Test Case 16 - Page 40
        KeyChain keyChain = fixedKeyChain(key, iv);
        CryptoConfig config = CryptoConfig.KEY_256;
        Crypto crypto = new Crypto(keyChain, new AndroidCryptoLibrary(), config);
        byte[] plainBytes = toBytes(plain);
        byte[] encrypted = crypto.encrypt(plainBytes, Entity.create(entityId));
        byte[] decrypted = crypto.decrypt(encrypted, Entity.create(entityId));
        Assert.assertFalse(Arrays.equals(encrypted, plainBytes));
        Assert.assertTrue(Arrays.equals(decrypted, plainBytes));

        try {
            crypto.decrypt(encrypted, Entity.utf16(entityId));
            Assert.fail("Decryption with old entity should have failed!");
        } catch (IOException ioe) {
            // ok, it shouldn't match!
        }
    }
}
