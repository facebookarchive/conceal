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

import java.util.Arrays;

import com.facebook.crypto.keychain.KeyChain;
import com.facebook.crypto.mac.NativeMac;

public class FakeKeyChain implements KeyChain {

  private final byte[] mKey = new byte[CryptoConfig.KEY_128.keyLength];
  private final byte[] mIV = new byte[CryptoConfig.KEY_128.ivLength];
  private final byte[] mMacKey = new byte[NativeMac.KEY_LENGTH];

  public FakeKeyChain() {
    Arrays.fill(mKey, (byte) CryptoTestUtils.KEY_BYTES);
    Arrays.fill(mIV, (byte) CryptoTestUtils.IV_BYTES);
    Arrays.fill(mMacKey, (byte) CryptoTestUtils.MAC_KEY_BYTES);
  }

  @Override
  public byte[] getCipherKey() {
    return mKey;
  }

  @Override
  public byte[] getMacKey() {
    return mMacKey;
  }

  @Override
  public byte[] getNewIV() {
    return mIV;
  }

  @Override
  public void destroyKeys() {
  }
}
