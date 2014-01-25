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

import javax.crypto.Mac;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

public class BaseMac {

  protected String name;
  protected Key key;
  protected AlgorithmParameterSpec spec;

  public BaseMac(String name, Key key, AlgorithmParameterSpec spec) {
    this.name = name;
    this.key = key;
    this.spec = spec;
  }

  public Mac getMac() throws NoSuchAlgorithmException,
      InvalidAlgorithmParameterException,
      InvalidKeyException {
    Mac mac = Mac.getInstance(name);
    if (spec == null) {
      mac.init(key);
    } else {
      mac.init(key, spec);
    }
    return mac;
  }
}
