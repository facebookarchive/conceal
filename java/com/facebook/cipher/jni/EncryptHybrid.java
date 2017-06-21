// Copyright 2004-present Facebook. All Rights Reserved.

package com.facebook.cipher.jni;

import com.facebook.crypto.proguard.annotations.DoNotStrip;
import com.facebook.jni.HybridData;

/**
 * JNI wrapper for Conceal's Encrypt object in C++.
 */
public class EncryptHybrid {
  // load native

  @DoNotStrip
  private final HybridData mHybridData;

  public EncryptHybrid(byte[] key, byte[] iv, byte[] entity) {
    mHybridData = initHybrid(key, iv, entity);
  }

  @DoNotStrip
  private EncryptHybrid(HybridData hybridData) {
    // to be constructed from C++
    mHybridData = hybridData;
  }

  private static native HybridData initHybrid(byte[] key, byte[] iv, byte[] entity);

  public native byte[] start();
  public native void write(
      byte[] src,
      int srcOffset,
      byte[] target,
      int targetOffset,
      int count);
  public native byte[] end();
}
