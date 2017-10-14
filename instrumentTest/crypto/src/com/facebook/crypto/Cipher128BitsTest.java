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

import java.util.Arrays;

import static com.facebook.crypto.CryptoTestUtils.fixedKeyChain;
import static com.facebook.crypto.CryptoTestUtils.toBytes;

/**
 * Tests encryption using 128-bits keys.
 * It uses examples from
 * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
 */
@TargetApi(Build.VERSION_CODES.GINGERBREAD)
public class Cipher128BitsTest extends InstrumentationTestCase {


    protected void setUp() throws Exception {
      SoLoader.init(this.getInstrumentation().getContext(), false);
    }

    public void testCases() throws Exception {
        // Test Case 3 - Page 29
        testCase(
                // key
                "feffe9928665731c6d6a8f9467308308",
                // iv
                "cafebabefacedbaddecaf888",
                // plain text
                "d9313225f88406e5a55909c5aff5269a" +
                "86a7a9531534f7da2e4c303d8a318a72" +
                "1c3c0c95956809532fcf0e2449a6b525" +
                "b16aedf5aa0de657ba637b391aafd255",
                // cipher text
                "42831ec2217774244b7221b784d0d49c" +
                "e3aa212f2c02a4e035c17e2329aca12e" +
                "21d514b25466931c7d8f6a5aac84aa05" +
                "1ba30b396a0aac973d58e091473f5985");
        // Test Case 4 - Page 30
        testCase(
                // key
                "feffe9928665731c6d6a8f9467308308",
                // iv
                "cafebabefacedbaddecaf888",
                // plain text
                "d9313225f88406e5a55909c5aff5269a" +
                "86a7a9531534f7da2e4c303d8a318a72" +
                "1c3c0c95956809532fcf0e2449a6b525" +
                "b16aedf5aa0de657ba637b39",
                // cipher text
                "42831ec2217774244b7221b784d0d49c" +
                "e3aa212f2c02a4e035c17e2329aca12e" +
                "21d514b25466931c7d8f6a5aac84aa05" +
                "1ba30b396a0aac973d58e091");
    }

    public void testCase(String key, String iv, String plain, String cipher) throws Exception {
        // Test Case 16 - Page 40
        KeyChain keyChain = fixedKeyChain(key, iv);
        CryptoConfig config = CryptoConfig.KEY_128;
        Crypto crypto = new Crypto(keyChain, new AndroidCryptoLibrary(), config);
        byte[] plainBytes = toBytes(plain);
        byte[] encrypted = crypto.encrypt(plainBytes, new Entity("whatever"));
        byte[] expected = toBytes(cipher);
        // remove initial 2 bytes + IV
        // remove final tag 16 bytes
        int metadataLength = config.getHeaderLength() + config.getTailLength();
        int prefix = metadataLength - config.tagLength;
        byte[] bareEncrypted = Arrays.copyOfRange(encrypted, prefix, encrypted.length - config.tagLength);
        Assert.assertTrue(Arrays.equals(expected, bareEncrypted));
    }
}
