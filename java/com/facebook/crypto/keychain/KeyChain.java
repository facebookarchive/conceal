/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto.keychain;

import com.facebook.crypto.exception.KeyChainException;

public interface KeyChain {

  /**
   * Returns the key to use for encipherment.
   * @throws KeyChainException
   */
  public byte[] getCipherKey() throws KeyChainException;

  /**
   * Returns the key to use for integrity operations.
   * @throws KeyChainException
   */
  public byte[] getMacKey() throws KeyChainException;

  /**
   * Gets a new IV to use for encipherment operations.
   * @throws KeyChainException
   */
  public byte[] getNewIV() throws KeyChainException;

  /**
   * Destroys the existing keys of the keychain.
   */
  public void destroyKeys();
}
