/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.android.crypto.keychain;

import java.util.Arrays;

import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.util.NativeCryptoLibrary;
import com.facebook.soloader.NativeLibrary;

/**
 * An implementation of {@link NativeCryptoLibrary} that uses
 * {@link SoLoader} to load the crypto libraries.
 */
public class AndroidCryptoLibrary extends NativeLibrary implements NativeCryptoLibrary {

  public AndroidCryptoLibrary() {
    super(Arrays.asList("fb", /* merged "concealcpp",*/ "concealjni"));
  }

  @Override
  public synchronized void ensureCryptoLoaded() throws CryptoInitializationException {
    try {
        super.ensureLoaded();
    } catch (RuntimeException re) {
      if (re.getMessage() != null && re.getMessage().contains("SoLoader.init")) {
        throw new RuntimeException(
            "SoLoader not initialized. Check https://github.com/helios175/conceal/blob/master/README.md#important-initializing-the-library-loader",
            re);
      }
      throw re;
    }
  }
}
