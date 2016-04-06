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
 * Represents a encryption configuration: key length, iv length, etc.
 * All lengths are in bytes.
 */
public enum CryptoConfig {

    KEY_128(16, 12, 64); // used in Conceal v1

    public final int keyLength;
    public final int ivLength;
    public final int macLength;

    CryptoConfig(int keyLength, int ivLength, int macLength) {
        this.keyLength = keyLength;
        this.ivLength = ivLength;
        this.macLength = macLength;
    };
}
