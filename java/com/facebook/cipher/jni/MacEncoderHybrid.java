// Copyright 2004-present Facebook. All Rights Reserved.

package com.facebook.cipher.jni;

import com.facebook.crypto.proguard.annotations.DoNotStrip;
import com.facebook.jni.HybridData;

/**
 * JNI wrapper for Conceal's MacEncoder object in C++.
 */
public class MacEncoderHybrid {
  // load native

  @DoNotStrip
  private final HybridData mHybridData;

  public MacEncoderHybrid(byte[] key, byte[] entity) {
    mHybridData = initHybrid(key, entity);
  }

  private static native HybridData initHybrid(byte[] key, byte[] entity);

  public native byte[] start();
  public native void write(byte[] data, int offset, int count);
  public native byte[] end();
}
