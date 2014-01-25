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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import com.facebook.crypto.exception.KeyChainException;
import com.facebook.crypto.mac.NativeMac;
import com.facebook.crypto.streams.NativeMacLayeredInputStream;
import com.facebook.crypto.streams.NativeMacLayeredOutputStream;
import com.facebook.crypto.cipher.NativeGCMCipher;
import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.keychain.KeyChain;
import com.facebook.crypto.streams.NativeGCMCipherInputStream;
import com.facebook.crypto.streams.NativeGCMCipherOutputStream;
import com.facebook.crypto.util.NativeCryptoLibrary;

public class Crypto {

  private final KeyChain mKeyChain;
  private final NativeCryptoLibrary mNativeCryptoLibrary;

  public Crypto(KeyChain keyChain, NativeCryptoLibrary nativeCryptoLibrary) {
    mKeyChain = keyChain;
    mNativeCryptoLibrary = nativeCryptoLibrary;
  }

  /**
   * Tells if crypto native library and this class can be used.
   * @return true if and only if libraries could be loaded successfully.
   */
  public boolean isAvailable() {
    try {
      mNativeCryptoLibrary.ensureCryptoLoaded();
      return true;
    } catch (Throwable t) {
      return false;
    }
  }

  /**
   * Gives you an output stream wrapper that encrypts the text written.
   *
   * @param cipherStream The stream that the encrypted data will be written to.
   * @param entity A unique object identifying what is being written.
   *
   * @return A ciphered output stream to write to.
   * @throws IOException
   */
  public OutputStream getCipherOutputStream(OutputStream cipherStream, Entity entity)
      throws IOException, CryptoInitializationException, KeyChainException {
    byte[] iv = mKeyChain.getNewIV();

    NativeGCMCipher gcmCipher = new NativeGCMCipher(mNativeCryptoLibrary);
    gcmCipher.encryptInit(mKeyChain.getCipherKey(), iv);
    cipherStream.write(iv);

    byte[] entityBytes = entity.getBytes();
    gcmCipher.updateAad(entityBytes, entityBytes.length);
    return new NativeGCMCipherOutputStream(cipherStream, gcmCipher);
  }

  /**
   * Gives you an input stream wrapper that decrypts another stream.
   * You must read the whole stream to completion, i.e. till -1. Failure
   * to do so may result in a security vulnerability.
   *
   * @param cipherStream The stream from which the encrypted data is read.
   * @param entity A unique object identifying what is being read.
   *
   * @return A ciphered input stream to read from.
   * @throws IOException
   */
  public InputStream getCipherInputStream(InputStream cipherStream, Entity entity)
      throws IOException, CryptoInitializationException, KeyChainException {
    byte[] iv = new byte[NativeGCMCipher.IV_LENGTH];

    int read = cipherStream.read(iv);
    if (read != iv.length) {
      throw new IOException("Not enough bytes for iv: " + read);
    }

    NativeGCMCipher gcmCipher = new NativeGCMCipher(mNativeCryptoLibrary);
    gcmCipher.decryptInit(mKeyChain.getCipherKey(), iv);

    byte[] entityBytes = entity.getBytes();
    gcmCipher.updateAad(entityBytes, entityBytes.length);
    return new NativeGCMCipherInputStream(cipherStream, gcmCipher);
  }

  /**
   * Gives you an output stream wrapper that adds some data to the stream which
   * can be used to ensure its integrity.
   *
   * @param stream The stream to which the data will be written
   * @param entity A unique object identifying what is being written.
   *
   * @return A ciphered input stream to read from.
   * @throws IOException
   */
  public OutputStream getMacOutputStream(OutputStream stream, Entity entity)
      throws IOException, KeyChainException, CryptoInitializationException {
    NativeMac nativeMac = new NativeMac(mNativeCryptoLibrary);
    byte[] macKey = mKeyChain.getMacKey();
    nativeMac.init(macKey, macKey.length);
    byte[] entityBytes = entity.getBytes();
    nativeMac.update(entityBytes, 0, entityBytes.length);
    return new NativeMacLayeredOutputStream(nativeMac, stream);
  }

  /**
   * Gives you an input stream wrapper that ensures the integrity of another
   * stream. You must read the whole stream to completion, i.e. till -1. Failure
   * to do so may result in a security vulnerability.
   *
   * @param stream The stream from which the data is read.
   * @param entity A unique object identifying what is being read.
   *
   * @return A ciphered input stream to read from.
   * @throws IOException
   */
  public InputStream getMacInputStream(InputStream stream, Entity entity)
      throws IOException, KeyChainException, CryptoInitializationException {
    NativeMac nativeMac = new NativeMac(mNativeCryptoLibrary);
    byte[] macKey = mKeyChain.getMacKey();
    nativeMac.init(macKey, macKey.length);
    byte[] entityBytes = entity.getBytes();
    nativeMac.update(entityBytes, 0, entityBytes.length);
    return new NativeMacLayeredInputStream(nativeMac, stream);
  }
}
