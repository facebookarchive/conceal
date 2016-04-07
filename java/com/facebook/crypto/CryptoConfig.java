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

    KEY_128((byte) 1, 16, 12, 16), // used in Conceal v1
    KEY_256((byte) 2, 32, 12, 16);

    public final byte cipherId;
    public final int keyLength;
    public final int ivLength;
    public final int tagLength;

    CryptoConfig(byte chiperId, int keyLength, int ivLength, int tagLength) {
        this.cipherId = chiperId;
        this.keyLength = keyLength;
        this.ivLength = ivLength;
        this.tagLength = tagLength;
    };
}
