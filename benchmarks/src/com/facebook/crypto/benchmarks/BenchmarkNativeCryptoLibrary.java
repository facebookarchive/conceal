/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto.benchmarks;

import android.annotation.SuppressLint;

import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.util.NativeCryptoLibrary;

@SuppressLint("SdCardPath")
public class BenchmarkNativeCryptoLibrary implements NativeCryptoLibrary {

  // This is a workaround the limitation that vogar cannot load native libraries.
  // The runner script will install an app, and thus create this package before
  // vogar is invoked. As a result, this path should always exist.
  private static final String PATH = "/data/data/com.facebook.crypto.benchmarks.app/lib/";
  private static final String LIB_FB = "libconceal.so";

  private boolean mLoadedCalled;

  @Override
  public void ensureCryptoLoaded() throws CryptoInitializationException {
    if (!mLoadedCalled) {
      loadLibraries();
    }
    mLoadedCalled = true;
  }

  public boolean loadLibraries() {
    try {
      System.load(PATH + LIB_FB);
    } catch (UnsatisfiedLinkError ule) {
      return false;
    }
    return true;
  }
}
