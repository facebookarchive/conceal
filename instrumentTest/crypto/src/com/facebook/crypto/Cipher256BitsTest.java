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

import com.facebook.crypto.keychain.KeyChain;
import com.facebook.crypto.util.SystemNativeCryptoLibrary;

import junit.framework.Assert;

import java.util.Arrays;

import static com.facebook.crypto.CryptoTestUtils.fixedKeyChain;
import static com.facebook.crypto.CryptoTestUtils.toBytes;

/**
 * Tests encryption using 256-bits keys.
 * It uses examples from
 * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
 */
@TargetApi(Build.VERSION_CODES.GINGERBREAD)
public class Cipher256BitsTest extends InstrumentationTestCase {


    protected void setUp() throws Exception {
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
                // cipher text
                "522dc1f099567d07f47f37a32a84427d" +
                "643a8cdcbfe5c0c97598a2bd2555d1aa" +
                "8cb08e48590dbb3da7b08b1056828838" +
                "c5f61e6393ba7a0abcc9f662898015ad");
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
                "522dc1f099567d07f47f37a32a84427d" +
                "643a8cdcbfe5c0c97598a2bd2555d1aa" +
                "8cb08e48590dbb3da7b08b1056828838" +
                "c5f61e6393ba7a0abcc9f662");
    }

        public void testCase(String key, String iv, String plain, String cipher) throws Exception {
        // Test Case 16 - Page 40
        KeyChain keyChain = fixedKeyChain(key, iv);
        CryptoConfig config = CryptoConfig.KEY_256;
        Crypto crypto = new Crypto(keyChain, new SystemNativeCryptoLibrary(), config);
        byte[] plainBytes = toBytes(plain);
        byte[] encrypted = crypto.encrypt(plainBytes, new Entity("whatever"));
        byte[] expected = toBytes(cipher);
        // remove initial 2 bytes + IV
        // remove final tag 16 bytes
        int metadataLength = crypto.getCipherMetaDataLength();
        int prefix = metadataLength - config.tagLength;
        byte[] bareEncrypted = Arrays.copyOfRange(encrypted, prefix, encrypted.length - config.tagLength);
        Assert.assertTrue(Arrays.equals(expected, bareEncrypted));
    }
}
