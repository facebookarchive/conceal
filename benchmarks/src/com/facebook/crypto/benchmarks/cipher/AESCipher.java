/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto.benchmarks.cipher;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class AESCipher extends BaseCipher {
  public AESCipher(AlgorithmParameterSpec spec, Key key) {
    super("AES/CTR/NoPadding", spec, key);
    setProvider(null);
  }

  public static AESCipher getInstance() {
    byte[] iv = new byte[16];
    byte[] key = new byte[16];
    SecureRandom random = new SecureRandom();
    random.nextBytes(iv);
    random.nextBytes(key);
    AlgorithmParameterSpec spec = new IvParameterSpec(iv);
    return new AESCipher(spec, new SecretKeySpec(key, "AES"));
  }
}
