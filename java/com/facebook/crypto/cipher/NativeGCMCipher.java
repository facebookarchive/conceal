/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
package com.facebook.crypto.cipher;

import java.util.Locale;

import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.util.Assertions;
import com.facebook.crypto.util.NativeCryptoLibrary;
import com.facebook.proguard.annotations.DoNotStrip;

/**
 * Various native functions to encrypt/decrypt data using GCM.
 */
@DoNotStrip
public class NativeGCMCipher {

  public static final String FAILURE = "Failure";

  private static final String CIPHER_ALREADY_INIT = "Cipher has already been initialized";
  private static final String CIPHER_NOT_INIT = "Cipher has not been initialized";
  private static final String CIPHER_NOT_FINALIZED = "Cipher has not been finalized";

  public static final int TAG_LENGTH = 16;
  public static final int KEY_LENGTH = 16;
  public static final int IV_LENGTH = 12;

  private STATE mCurrentState = STATE.UNINITIALIZED;

  private final NativeCryptoLibrary mNativeCryptoLibrary;

  private enum STATE {
    UNINITIALIZED,
    ENCRYPT_INITIALIZED,
    DECRYPT_INITIALIZED,
    ENCRYPT_FINALIZED,
    DECRYPT_FINALIZED,
  };

  public NativeGCMCipher(NativeCryptoLibrary nativeCryptoLibrary) {
    mNativeCryptoLibrary = nativeCryptoLibrary;
  }

  public void encryptInit(byte[] key, byte[] iv)
      throws NativeGCMCipherException, CryptoInitializationException {
    Assertions.checkState(mCurrentState == STATE.UNINITIALIZED, CIPHER_ALREADY_INIT);
    mNativeCryptoLibrary.ensureCryptoLoaded();
    if (nativeEncryptInit(key, iv) == nativeFailure()) {
      throw new NativeGCMCipherException("encryptInit");
    }
    mCurrentState = STATE.ENCRYPT_INITIALIZED;
  }
  public void decryptInit(byte[] key, byte[] iv)
      throws NativeGCMCipherException, CryptoInitializationException {
    Assertions.checkState(mCurrentState == STATE.UNINITIALIZED, CIPHER_ALREADY_INIT);
    mNativeCryptoLibrary.ensureCryptoLoaded();
    if (nativeDecryptInit(key, iv) == nativeFailure()) {
      throw new NativeGCMCipherException("decryptInit");
    }
    mCurrentState = STATE.DECRYPT_INITIALIZED;
  }

  public int update(byte[] data, int offset, int dataLen, byte[] output)
      throws NativeGCMCipherException {
    ensureInInitalizedState();
    int bytesRead = nativeUpdate(data, offset, dataLen, output);
    if (bytesRead < 0) {
      throw new NativeGCMCipherException(
          formatStrLocaleSafe(
              "update: Offset = %d; DataLen = %d; Result = %d",
              offset,
              dataLen,
              bytesRead));
    }
    return bytesRead;
  }

  public void updateAad(byte[] data, int dataLength)
      throws NativeGCMCipherException {
    ensureInInitalizedState();
    if (nativeUpdateAad(data, dataLength) < 0) {
      throw new NativeGCMCipherException(
          formatStrLocaleSafe("updateAAd: DataLen = %d", dataLength));
    }
  }

  public void encryptFinal(byte[] tag, int tagLen)
      throws NativeGCMCipherException {
    Assertions.checkState(mCurrentState == STATE.ENCRYPT_INITIALIZED, CIPHER_NOT_INIT);
    mCurrentState = STATE.ENCRYPT_FINALIZED;
    if (nativeEncryptFinal(tag, tagLen) == nativeFailure()) {
      throw new NativeGCMCipherException(
          formatStrLocaleSafe("encryptFinal: %d", tagLen));
    }
  }

  public void decryptFinal(byte[] expectedTag, int tagLen) throws NativeGCMCipherException {
    Assertions.checkState(mCurrentState == STATE.DECRYPT_INITIALIZED, CIPHER_NOT_INIT);
    mCurrentState = STATE.DECRYPT_FINALIZED;
    if (nativeDecryptFinal(expectedTag, tagLen) == nativeFailure()) {
      throw new NativeGCMCipherException("decryptFinal");
    }
  }

  public void destroy() throws NativeGCMCipherException {
    ensureInFinalizedState();
    if (nativeDestroy() == nativeFailure()) {
      throw new NativeGCMCipherException("destroy");
    }
    mCurrentState = STATE.UNINITIALIZED;
  }

  public int getCipherBlockSize() {
    ensureInInitalizedState();
    return nativeGetCipherBlockSize();
  }

  private void ensureInInitalizedState() {
    boolean initialized =
        mCurrentState == STATE.DECRYPT_INITIALIZED ||
        mCurrentState == STATE.ENCRYPT_INITIALIZED;
    Assertions.checkState(initialized, CIPHER_NOT_INIT);
  }

  private void ensureInFinalizedState() {
    boolean finalized =
        mCurrentState == STATE.DECRYPT_FINALIZED ||
        mCurrentState == STATE.ENCRYPT_FINALIZED;
    Assertions.checkState(finalized, CIPHER_NOT_FINALIZED);
  }

  private String formatStrLocaleSafe(String format, Object... args) {
    return String.format((Locale)null, format, args);
  }

  // Used to store the GCM cipher context.
  @DoNotStrip
  private int mCtxPtr;

  // The integer value representing failure in JNI world.
  private static native int nativeFailure();

  private native int nativeEncryptInit(byte[] key, byte[] iv);
  private native int nativeDecryptInit(byte[] key, byte[] iv);

  private native int nativeUpdate(byte[] data, int offset, int dataLen, byte[] output);
  private native int nativeUpdateAad(byte[] data, int dataLength);

  private native int nativeEncryptFinal(byte[] tag, int tagLen);
  private native int nativeDecryptFinal(byte[] tag, int tagLength);

  private native int nativeDestroy();

  private native int nativeGetCipherBlockSize();
}
