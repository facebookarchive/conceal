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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import com.facebook.crypto.CryptoConfig;
import com.facebook.crypto.benchmarks.BenchmarkNativeCryptoLibrary;
import com.facebook.crypto.cipher.NativeGCMCipher;
import com.facebook.crypto.util.NativeCryptoLibrary;
import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.streams.NativeGCMCipherInputStream;
import com.facebook.crypto.streams.NativeGCMCipherOutputStream;

public class NativeGCMCipherHelper {

  private static final NativeCryptoLibrary mNativeCryptoLibrary =
      new BenchmarkNativeCryptoLibrary();

  private final byte[] mKey;
  private final byte[] mIv;
  private final int mTagLength;

  public NativeGCMCipherHelper(byte[] key, byte[] iv, int tagLength) {
    this.mKey = key.clone();
    this.mIv = iv.clone();
    mTagLength = tagLength;
  }

  public static NativeGCMCipherHelper getInstance() {
    byte[] key = new byte[CryptoConfig.KEY_128.keyLength];
    byte[] iv = new byte[CryptoConfig.KEY_128.ivLength];
    new SecureRandom().nextBytes(key);
    new SecureRandom().nextBytes(iv);
    return new NativeGCMCipherHelper(key, iv, CryptoConfig.KEY_128.tagLength);
  }

  public OutputStream getOutputStream(OutputStream cipherStream, byte[] encryptBuffer)
      throws IOException, CryptoInitializationException {
    NativeGCMCipher gcmCipher = new NativeGCMCipher(mNativeCryptoLibrary);
    gcmCipher.encryptInit(mKey, mIv);
    cipherStream.write(mIv);

    return new NativeGCMCipherOutputStream(cipherStream, gcmCipher, encryptBuffer, mTagLength);
  }

  public InputStream getInputStream(InputStream cipherStream)
      throws IOException, CryptoInitializationException {
    byte[] iv = new byte[CryptoConfig.KEY_128.ivLength];
    cipherStream.read(iv);
    NativeGCMCipher gcmCipher = new NativeGCMCipher(mNativeCryptoLibrary);
    gcmCipher.decryptInit(mKey, iv);

    return new NativeGCMCipherInputStream(cipherStream, gcmCipher, mTagLength);
  }
}
