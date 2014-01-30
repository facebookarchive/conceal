/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto;

/**
 * Represents the current versions and IDs of the crypto operations.
 */
/* package */ class VersionCodes {

  /**
   * Identifier of the cipher serialization version.
   */
  public static final byte CIPHER_SERALIZATION_VERSION = 1;

  /**
   * Identifier for the cipher algorithm and the framing method used.
   */
  public static final byte CIPHER_ID = 1;

  /**
   * Identifier for the mac serialization version.
   */
  public static final byte MAC_SERIALIZATION_VERSION = 1;

  /**
   * Identifier for the mac algorithm and the framing method used.
   */
  public static final byte MAC_ID = 1;
}
