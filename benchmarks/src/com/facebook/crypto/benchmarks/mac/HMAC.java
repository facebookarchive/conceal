/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto.benchmarks.mac;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Random;

public class HMAC extends BaseMac {

  public HMAC(Key key, AlgorithmParameterSpec spec) {
    super("HmacSHA1", key, spec);
  }

  public static HMAC getInstance() {
    byte[] key = new byte[16];
    Random random = new Random();
    random.nextBytes(key);
    return new HMAC(new SecretKeySpec(key, "AES"), null);
  }
}
