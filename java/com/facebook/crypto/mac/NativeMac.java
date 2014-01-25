/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto.mac;

import java.io.IOException;

import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.util.Assertions;
import com.facebook.crypto.util.NativeCryptoLibrary;
import com.facebook.proguard.annotations.DoNotStrip;

@DoNotStrip
public class NativeMac {

  public static final String FAILURE = "Failure";
  public static final int KEY_LENGTH = 64;

  private static final String MAC_ALREADY_INIT = "Mac has already been initialized";
  private static final String MAC_NOT_INIT = "Mac has not been initialized";
  private static final String MAC_NOT_FINALIZED = "Mac has not been finalized";

  private STATE mCurrentState = STATE.UNINITIALIZED;

  private final NativeCryptoLibrary mNativeCryptoLibrary;

  private enum STATE {
    UNINITIALIZED,
    INITIALIZED,
    FINALIZED,
  };

  public NativeMac(NativeCryptoLibrary nativeCryptoLibrary) {
    mNativeCryptoLibrary = nativeCryptoLibrary;
  }

  public void init(byte[] key, int len) throws CryptoInitializationException, IOException {
    Assertions.checkState(mCurrentState == STATE.UNINITIALIZED, MAC_ALREADY_INIT);
    mNativeCryptoLibrary.ensureCryptoLoaded();
    if (nativeInit(key, len) == nativeFailure()) {
      throw new IOException(FAILURE);
    }
    mCurrentState = STATE.INITIALIZED;
  }

  public void update(byte read) throws IOException {
    Assertions.checkState(mCurrentState == STATE.INITIALIZED, MAC_NOT_INIT);
    if (nativeUpdate(read) == nativeFailure()) {
      throw new IOException(FAILURE);
    }
  }

  public void update(byte[] buffer, int offset, int len) throws IOException {
    Assertions.checkState(mCurrentState == STATE.INITIALIZED, MAC_NOT_INIT);
    if (nativeUpdate(buffer, offset, len) == nativeFailure()) {
      throw new IOException(FAILURE);
    }
  }

  public byte[] doFinal() throws IOException {
    Assertions.checkState(mCurrentState == STATE.INITIALIZED, MAC_NOT_INIT);
    mCurrentState = STATE.FINALIZED;
    byte[] toReturn = nativeDoFinal();
    if (toReturn == null) {
      throw new IOException(FAILURE);
    }

    return toReturn;
  }

  public void destroy() throws IOException {
    Assertions.checkState(mCurrentState == STATE.FINALIZED, MAC_NOT_FINALIZED);
    if (nativeDestroy() == nativeFailure()) {
      throw new IOException(FAILURE);
    }
    mCurrentState = STATE.UNINITIALIZED;
  }

  public int getMacLength() {
    return nativeGetMacLength();
  }

  // Used to store the HMAC context.
  @DoNotStrip
  private int mCtxPtr;

  // The integer value representing failure in JNI world.
  private static native int nativeFailure();

  private native int nativeInit(byte[] key, int len);

  private native int nativeUpdate(byte read);
  private native int nativeUpdate(byte[] buffer, int offset, int len);

  private native byte[] nativeDoFinal();

  private native int nativeDestroy();

  private native int nativeGetMacLength();
}
