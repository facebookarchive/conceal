/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto.keygen;

import java.nio.charset.Charset;
import java.security.SecureRandom;

import com.facebook.cipher.jni.PBKDF2Hybrid;
import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.util.NativeCryptoLibrary;

/**
 * Generates encryption keys derived from arbitrary String passwords.
 * Implementation of PBKDF2: Password-Based Key Derivation Function v2.
 * https://en.wikipedia.org/wiki/PBKDF2
 * It uses OpenSSL's PBKDF2-HMAC-SHA256.
 * <p>
 * Caller provides a password and optionally the salt to use.
 * If not provided a random 128-bit salt will be used and can be retrieved with getSalt().
 * Iterations can be set before calling.
 * <p>
 * Usage:
 * <code>
 *   byte[] key =
 *     new PasswordBasedKeyDerivation(nativeCryptoLibrary)
 *       .setIterations(10000)
 *       .setPassword("P4$$word")
 *       .setSalt(buffer)
 *       .setKeyLengthInBytes(16) // in bytes
 *       .generate();
 * </code>
 * <p>
 * Bear in mind that SecureRandom will be used to automatically generate a default salt.
 * Android's SecureRandom implementation is not secure and SecureRandomFix must be invoked first.
 * See {@link com.facebook.android.crypto.keychain.SecureRandomFix}
 */
public class PasswordBasedKeyDerivation {

  private static final int MINIMUM_SALT_LENGTH = 4;
  private static final int DEFAULT_SALT_LENGTH = 16;

  public static final int MINIMUM_ITERATIONS = 1;
  public static final int DEFAULT_ITERATIONS = 4096;

  public static final int MINIMUM_KEY_LENGTH = 8;
  public static final int DEFAULT_KEY_LENGTH = 16;

  private static final Charset UTF_8 = Charset.forName("UTF-8");

  private final NativeCryptoLibrary mNativeLibrary;
  private final SecureRandom mSecureRandom;

  private int mIterations;
  private String mPassword;
  private byte[] mSalt;
  private int mKeyLengthInBytes;
  private byte[] mGeneratedKey;

  /**
   * @param secureRandom this will be used to generate the salt.
   *                     Use FixedSecureRandom for Android, never java.util.SecureRandom.
   */
  public PasswordBasedKeyDerivation(SecureRandom secureRandom, NativeCryptoLibrary library) {
    mSecureRandom = secureRandom;
    mNativeLibrary = library;
    mIterations = DEFAULT_ITERATIONS;
    mKeyLengthInBytes = DEFAULT_KEY_LENGTH;
  }

  public PasswordBasedKeyDerivation setIterations(int iterations) {
    if (iterations < MINIMUM_ITERATIONS) {
      throw new IllegalArgumentException("Iterations cannot be less than " + MINIMUM_ITERATIONS);
    }
    mIterations = iterations;
    return this;
  }

  public PasswordBasedKeyDerivation setPassword(String password) {
    if (password == null) {
      throw new IllegalArgumentException("Password cannot be null");
    }
    mPassword = password;
    return this;
  }

  public PasswordBasedKeyDerivation setSalt(byte[] salt) {
    if (salt != null && salt.length < MINIMUM_SALT_LENGTH) {
      throw new IllegalArgumentException("Salt cannot be shorter than 8 bytes");
    }
    mSalt = salt;
    return this;
  }

  public PasswordBasedKeyDerivation setKeyLengthInBytes(int keyLengthInBytes) {
    if (keyLengthInBytes < MINIMUM_KEY_LENGTH) {
      throw new IllegalArgumentException("Key length cannot be less than 8 bytes");
    }
    mKeyLengthInBytes = keyLengthInBytes;
    return this;
  }

  public byte[] generate() throws CryptoInitializationException {
    if (mPassword == null) {
      throw new IllegalStateException("Password was not set");
    }
    // for now the random salt generation happens in Java
    if (mSalt == null) {
      mSalt = new byte[DEFAULT_SALT_LENGTH];
      mSecureRandom.nextBytes(mSalt);
    }
    mNativeLibrary.ensureCryptoLoaded();
    PBKDF2Hybrid pbkdf2 = new PBKDF2Hybrid();
    pbkdf2.setIterations(mIterations);
    byte[] password = mPassword.getBytes(UTF_8);
    pbkdf2.setPassword(password, 0, password.length);
    pbkdf2.setSalt(mSalt, 0, mSalt.length);
    pbkdf2.setKeyLengthInBytes(mKeyLengthInBytes);
    mGeneratedKey = pbkdf2.generate();
    return mGeneratedKey;
  }

  public int getIterations() {
    return mIterations;
  }

  public String getPassword() {
    return mPassword;
  }

  public byte[] getSalt() {
    return mSalt;
  }

  public int getKeyLengthInBytes() {
    return mKeyLengthInBytes;
  }

  public byte[] getGeneratedKey() {
    return mGeneratedKey;
  }
}
