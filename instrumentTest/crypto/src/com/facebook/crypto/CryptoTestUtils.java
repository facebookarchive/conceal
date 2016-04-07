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

import com.facebook.crypto.exception.KeyChainException;
import com.facebook.crypto.keychain.KeyChain;

import java.io.ByteArrayOutputStream;

public class CryptoTestUtils {
  public static final int NUM_DATA_BYTES = 2752;
  public static final int KEY_BYTES = 42;
  public static final int MAC_KEY_BYTES = 44;
  public static final int IV_BYTES = 43;
  public static final String ENTITY_NAME = "TEST";
  public static final String FAKE_ENTITY_NAME = "FAKE";

  // Failure messages.
  public static final String DATA_IS_NOT_ENCRYPTED = "Data is not encrypted.";
  public static final String DECRYPTED_DATA_IS_DIFFERENT = "Decrypted data is different";
  public static final String ENCRYPTED_DATA_IS_DIFFERENT = "Encrypted data is different";
  public static final String ENCRYPTED_DATA_OF_DIFFERENT_LENGTH =
      "Encrypted data is of different length";
  public static final String EXCEPTION_EXPECTED = "Exception expected";
  public static final String UNEXPECTED_EXCEPTION_THROWN = "Unexpected exception thrown";
  public static final String CRYPTO_INITIALIZATION_ERROR = "Crypto Initialization Error";
  public static final String EXPECTED_DATA_NOT_ZERO =
      "Expected bytes is not zero after reading the entire stream";
  public static final String WRONG_EXPECTED_NUMBER_OF_BYTES =
      "The expected number of bytes written is incorrect";
  public static final String ENCRYPTED_DATA_NULL = "Encrypted data is null";
  public static final String KEY_NOT_FOUND = "Key not found";
  public static final String ENCRYPTED_DATA_DOES_NOT_MATCH = "Encrypted data does not match";
  public static final String TAG_DOES_NOT_MATCH = "Tag does not match";
  public static final String WRONG_METADATA_LENGTH = "Crypto doesn't return right metadata length";

  public static KeyChain fixedKeyChain(final String key, final String iv) {
    return new KeyChain() {

      private final byte[] mKey = toBytes(key);
      private final byte[] mIV = toBytes(iv);

      @Override
      public byte[] getCipherKey() throws KeyChainException {
        return mKey;
      }

      @Override
      public byte[] getMacKey() throws KeyChainException {
        throw new UnsupportedOperationException();
      }

      @Override
      public byte[] getNewIV() throws KeyChainException {
        return mIV;
      }

      @Override
      public void destroyKeys() {
        // nothing
      }
    };
  }

  private static final String VALID = "0123456789abcdef0123456789ABCDEF";

  public static byte[] toBytes(String hexa) {
    boolean second = false;
    int current = 0;
    ByteArrayOutputStream baos = new ByteArrayOutputStream(hexa.length() / 2);
    for (int i = 0; i < hexa.length(); i++) {
      char c = hexa.charAt(i);
      int value = VALID.indexOf(c) % 16;
      if (value < 0) {
        continue;
      }
      if (second) {
        current += value;
        second = false;
        baos.write(current);
      } else {
        current = value * 16;
        second = true;
      }
    }
    return baos.toByteArray();
  }
}
