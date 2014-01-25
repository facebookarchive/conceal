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

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import com.facebook.crypto.streams.BetterCipherInputStream;

public class BaseCipher {

  protected AlgorithmParameterSpec mAlgorithmParameterSpec;
  protected String mName;
  protected Key mKey;
  protected String mProvider;

  public BaseCipher(String name, AlgorithmParameterSpec spec, Key key) {
    this.mAlgorithmParameterSpec = spec;
    this.mName = name;
    this.mKey = key;
  }

  protected void setProvider(String prov) {
    mProvider = prov;
  }

  public InputStream getInputStream(InputStream is) throws NoSuchProviderException,
      InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException,
      NoSuchPaddingException {
    return new BetterCipherInputStream(is, getDecrypt());
  }

  public OutputStream getOutputStream(OutputStream os) throws NoSuchProviderException,
      InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException,
      NoSuchPaddingException {
    return new CipherOutputStream(os, getEncrypt());
  }

  private Cipher getEncrypt()
      throws NoSuchPaddingException,
      NoSuchAlgorithmException,
      InvalidAlgorithmParameterException,
      InvalidKeyException,
      NoSuchProviderException {
    Cipher cipher;
    if (mProvider != null) {
      cipher = Cipher.getInstance(mName, mProvider);
    } else {
      cipher = Cipher.getInstance(mName);
    }
    cipher.init(Cipher.ENCRYPT_MODE, mKey, mAlgorithmParameterSpec);
    return cipher;
  }

  private Cipher getDecrypt()
      throws NoSuchPaddingException,
      NoSuchAlgorithmException,
      InvalidAlgorithmParameterException,
      InvalidKeyException,
      NoSuchProviderException {
    Cipher cipher;
    if (mProvider != null) {
      cipher = Cipher.getInstance(mName, mProvider);
    } else {
      cipher = Cipher.getInstance(mName);
    }

    cipher.init(Cipher.DECRYPT_MODE, mKey, mAlgorithmParameterSpec);
    return cipher;
  }
}
