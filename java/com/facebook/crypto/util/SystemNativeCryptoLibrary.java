/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto.util;

import java.util.ArrayList;

import com.facebook.crypto.exception.CryptoInitializationException;

/**
 * An implementation of {@link NativeCryptoLibrary} that uses
 * {@link System#loadLibrary(String)} to load the crypto libraries.
 */
public class SystemNativeCryptoLibrary implements NativeCryptoLibrary {

  private static final ArrayList<String> LIBS = new ArrayList<String>() {{
    add("cryptox");
    add("conceal");
  }};

  private boolean mLoadLibraries;
  private boolean mLibrariesLoaded;
  private volatile UnsatisfiedLinkError mLinkError;

  public SystemNativeCryptoLibrary() {
    mLoadLibraries = true;
    mLibrariesLoaded = false;
    mLinkError = null;
  }

  @Override
  public synchronized void ensureCryptoLoaded() throws CryptoInitializationException {
    if (!loadLibraries()) {
      throw new CryptoInitializationException(mLinkError);
    }
  }

  private synchronized boolean loadLibraries() {
    if (!mLoadLibraries) {
      return mLibrariesLoaded;
    }
    try {
      for (String name : LIBS) {
        System.loadLibrary(name);
      }
      mLibrariesLoaded = true;
    } catch (UnsatisfiedLinkError error) {
      mLinkError = error;
      mLibrariesLoaded = false;
    }
    mLoadLibraries = false;
    return mLibrariesLoaded;
  }
}
