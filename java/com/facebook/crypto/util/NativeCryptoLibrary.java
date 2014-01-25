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

import com.facebook.crypto.exception.CryptoInitializationException;

/**
 * Represents the native libraries for cryptographic utils.
 */
public interface NativeCryptoLibrary {

  /**
   * loads libraries (if not loaded yet), throws on failure.
   * @throws CryptoInitializationException
   */
  public void ensureCryptoLoaded() throws CryptoInitializationException;
}
