// Copyright 2004-present Facebook. All Rights Reserved.

package com.facebook.cipher.jni;

import com.facebook.crypto.proguard.annotations.DoNotStrip;
import com.facebook.jni.HybridData;

/**
 * JNI wrapper for Conceal's MacEncoder object in C++.
 */
public class PBKDF2Hybrid {
  // load native

  @DoNotStrip
  private final HybridData mHybridData;

  public PBKDF2Hybrid() {
    mHybridData = initHybrid();
  }

  private static native HybridData initHybrid();

  public native void setIterations(int iterations);
  public native void setPassword(byte[] password, int offset, int count);
  public native void setSalt(byte[] salt, int offset, int count);
  public native void setKeyLengthInBytes(int keyLength);
  public native byte[] generate();
  public native byte[] getKey();
  public native byte[] getSalt();
}
