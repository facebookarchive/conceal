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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import com.facebook.crypto.benchmarks.BenchmarkNativeCryptoLibrary;
import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.mac.NativeMac;
import com.facebook.crypto.util.NativeCryptoLibrary;
import com.facebook.crypto.streams.NativeMacLayeredInputStream;
import com.facebook.crypto.streams.NativeMacLayeredOutputStream;

public class NativeMacHelper {

  public final byte[] key;

  private static final NativeCryptoLibrary mNativeCryptoLibrary =
      new BenchmarkNativeCryptoLibrary();

  public NativeMac getMac() throws IOException, CryptoInitializationException {
    NativeMac mac = new NativeMac(mNativeCryptoLibrary);
    mac.init(key, key.length);
    return mac;
  }

  private NativeMacHelper(byte[] key) {
    this.key = key;
  }

  public static NativeMacHelper getInstance() {
    byte[] key = new byte[NativeMac.KEY_LENGTH];
    new SecureRandom().nextBytes(key);
    return new NativeMacHelper(key);
  }

  public OutputStream getOutputStream(OutputStream rawStream)
      throws IOException, CryptoInitializationException {
    return new NativeMacLayeredOutputStream(getMac(), rawStream);
  }

  public InputStream getInputStream(InputStream rawStream)
      throws IOException, CryptoInitializationException {
    return new NativeMacLayeredInputStream(getMac(), rawStream);
  }
}
