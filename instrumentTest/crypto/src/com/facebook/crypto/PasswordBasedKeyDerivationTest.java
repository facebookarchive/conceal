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

import com.facebook.android.crypto.keychain.AndroidConceal;
import com.facebook.crypto.keygen.PasswordBasedKeyDerivation;
import com.facebook.crypto.util.SystemNativeCryptoLibrary;

import java.util.Arrays;

import android.annotation.TargetApi;
import android.os.Build;
import android.test.InstrumentationTestCase;

/**
 * Tests for PasswordBasedKeyDerivation based on PBKDF2-HMAC-SHA256 test vector:
 * Based on http://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors
 * Removed: long test (2^24 iterations) and test with char \0 in password
 */

@TargetApi(Build.VERSION_CODES.GINGERBREAD)
public class PasswordBasedKeyDerivationTest extends InstrumentationTestCase {

  public void testCases() throws Exception {
    testOneCase("password", "salt", 1, 32, "12 0f b6 cf fc f8 b3 2c 43 e7 22 52 56 c4 f8 37 a8 65 48 c9 2c cc 35 48 08 05 98 7c b7 0b e1 7b");
    testOneCase("password", "salt", 2, 32, "ae 4d 0c 95 af 6b 46 d3 2d 0a df f9 28 f0 6d d0 2a 30 3f 8e f3 c2 51 df d6 e2 d8 5a 95 47 4c 43");
    testOneCase("password", "salt", 4096, 32, "c5 e4 78 d5 92 88 c8 41 aa 53 0d b6 84 5c 4c 8d 96 28 93 a0 01 ce 4e 11 a4 96 38 73 aa 98 13 4a");
    testOneCase("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40,
        "34 8c 89 db cb d3 2b 2f 32 d8 14 b8 11 6e 84 cf 2b 17 34 7e bc 18 00 18 1c 4e 2a 1f b8 dd 53 e1 c6 35 51 8c 7d ac 47 e9");
  }

  private void testOneCase(String password, String saltString, int iterations, int keyLength, String hexResult) throws Exception {
    byte[] salt = saltString.getBytes("ASCII");
    byte[] key = AndroidConceal.get().createPasswordBasedKeyDerivation()
        .setPassword(password) // it converts to c-char* using UTF8 which is equal to ASCII for 0-127
        .setSalt(salt)
        .setIterations(iterations)
        .setKeyLengthInBytes(keyLength)
        .generate();
    byte[] expected = toBytes(hexResult);
    assertTrue(Arrays.equals(expected, key));
  }

  private byte[] toBytes(String hexValue) {
    StringBuilder sb = new StringBuilder();
    for (int i=0; i<hexValue.length(); i++) {
      char c = hexValue.charAt(i);
      if (c != ' ') {
        sb.append(c);
      }
    }
    hexValue = sb.toString();
    int length = hexValue.length() / 2;
    byte[] result = new byte[length];
    for (int i=0; i<length; i++) {
      int offset = i*2;
      result[i] = (byte) Integer.parseInt(hexValue.substring(offset, offset+2), 16);
    }
    return result;
  }
}
