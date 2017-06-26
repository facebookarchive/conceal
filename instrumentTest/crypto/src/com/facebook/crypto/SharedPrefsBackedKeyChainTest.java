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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Random;

import com.facebook.android.crypto.keychain.AndroidCryptoLibrary;
import com.facebook.android.crypto.keychain.SharedPrefsBackedKeyChain;
import com.facebook.crypto.CryptoConfig;
import com.facebook.crypto.keychain.KeyChain;
import com.facebook.crypto.util.NativeCryptoLibrary;
import com.facebook.soloader.SoLoader;

import android.annotation.TargetApi;
import android.os.Build;
import android.test.InstrumentationTestCase;

import com.google.common.io.ByteStreams;
import com.google.common.io.Closeables;

@TargetApi(Build.VERSION_CODES.GINGERBREAD)
public class SharedPrefsBackedKeyChainTest extends InstrumentationTestCase {

  protected void setUp() throws Exception {
    SoLoader.init(this.getInstrumentation().getContext(), false);
  }

    public void testLegacy128Bits() throws Exception {
        KeyChain keyChain = new SharedPrefsBackedKeyChain(this.getInstrumentation().getContext());
        // destroy keys if they were present in prefs from previous test
        keyChain.destroyKeys();
        byte[] key = keyChain.getCipherKey();
        assertEquals(16, key.length);

        KeyChain keyChain2 = new SharedPrefsBackedKeyChain(this.getInstrumentation().getContext());
        byte[] key2 = keyChain.getCipherKey();
        assertTrue(Arrays.equals(key, key2));
    }

    public void test256Bits() throws Exception {
        KeyChain keyChain =
                new SharedPrefsBackedKeyChain(
                        this.getInstrumentation().getContext(),
                        CryptoConfig.KEY_256);
        // destroy keys if they were present in prefs from previous test
        keyChain.destroyKeys();
        byte[] key = keyChain.getCipherKey();
        assertEquals(32, key.length);

        KeyChain keyChain2 = new SharedPrefsBackedKeyChain(this.getInstrumentation().getContext());
        byte[] key2 = keyChain.getCipherKey();
        assertTrue(Arrays.equals(key, key2));
    }
}
