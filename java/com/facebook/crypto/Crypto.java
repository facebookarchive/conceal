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

import com.facebook.cipher.Cipher;
import com.facebook.cipher.Mac;
import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.exception.KeyChainException;
import com.facebook.crypto.keychain.KeyChain;
import com.facebook.crypto.util.NativeCryptoLibrary;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * This is still the one-stop place to get encryption and mac for streams and byte[].
 * The new code that was implementing encryption based on new Conceal++ is now moved
 * to @link {com.facebook.cipher.Cipher} and we delegate from here.
 * We will offer a different but analogous object to Cipher, for MAC purposes, so we don't
 * have a one-object-for-everything as this class is now.
 */
public class Crypto {

  private final Cipher mCipher;
  private final Mac mMac;
  private final NativeCryptoLibrary mNativeCryptoLibrary;

  /**
   * @deprecated Use ConcealAndroid.get().createCrypto(...)
   */
  @Deprecated
  public Crypto(KeyChain keyChain, NativeCryptoLibrary nativeCryptoLibrary) {
    this(keyChain, nativeCryptoLibrary, CryptoConfig.KEY_128);
  }

  public Crypto(KeyChain keyChain, NativeCryptoLibrary nativeCryptoLibrary, CryptoConfig config) {
    mCipher = new Cipher(nativeCryptoLibrary, config, keyChain);
    mMac = new Mac(nativeCryptoLibrary, keyChain);
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
   * Invokes getCipherOutputStream(cipherStream, entity, null)
   * @deprecated Use @link{#decryptFrom} instead.
   */
  @Deprecated
  public OutputStream getCipherOutputStream(OutputStream cipherStream, Entity entity)
          throws IOException, CryptoInitializationException, KeyChainException {
    return mCipher.encryptTo(cipherStream, entity, null);
  }

  /**
   * Gives you an output stream wrapper that encrypts the text written.
   *
   * @param cipherStream The stream that the encrypted data will be written to.
   * @param entity A unique object identifying what is being written.
   * @param encryptBuffer an auxiliar buffer used to encrypt the content
   *                      if null a new one will be created (size: 256+tagSize)
   *
   * @return A ciphered output stream to write to.
   * @throws IOException
   * @deprecated Use @link{#encryptTo} instead.
   */
  @Deprecated
  public OutputStream getCipherOutputStream(
      OutputStream cipherStream,
      Entity entity,
      byte[] encryptBuffer) throws IOException, CryptoInitializationException, KeyChainException {
    return mCipher.encryptTo(cipherStream, entity, encryptBuffer);
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
   * @throws CryptoInitializationException Thrown if the crypto libraries could not be initialized.
   * @throws KeyChainException Thrown if there is trouble managing keys.
   */
  public InputStream getCipherInputStream(InputStream cipherStream, Entity entity)
      throws IOException, CryptoInitializationException, KeyChainException {
    return mCipher.decryptFrom(cipherStream, entity);
  }

  /**
   * A convenience method to encrypt data if the data to be processed is small and can
   * be held in memory.
   * @param plainTextBytes Bytes of the plain text.
   * @param entity Entity to process.
   * @return cipherText.
   * @throws KeyChainException
   * @throws CryptoInitializationException
   * @throws IOException
   * @throws CryptoInitializationException Thrown if the crypto libraries could not be initialized.
   * @throws KeyChainException Thrown if there is trouble managing keys.
   */
  public byte[] encrypt(byte[] plainTextBytes, Entity entity)
      throws KeyChainException, CryptoInitializationException, IOException {
    return mCipher.encrypt(plainTextBytes, entity);
  }

  /**
   * A convenience method to decrypt data if the data to be processed is small and can
   * be held in memory.
   * @param cipherTextBytes Bytes of the cipher text.
   * @param entity Entity to process.
   * @return cipherText.
   * @throws IOException
   * @throws CryptoInitializationException Thrown if the crypto libraries could not be initialized.
   * @throws KeyChainException Thrown if there is trouble managing keys.
   */
  public byte[] decrypt(byte[] cipherTextBytes, Entity entity)
      throws KeyChainException, CryptoInitializationException, IOException {
    return mCipher.decrypt(cipherTextBytes, entity);
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
   * @throws CryptoInitializationException Thrown if the crypto libraries could not be initialized.
   * @throws KeyChainException Thrown if there is trouble managing keys.
   */
  public OutputStream getMacOutputStream(OutputStream stream, Entity entity)
      throws IOException, KeyChainException, CryptoInitializationException {
    return mMac.macTo(stream, entity);
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
   * @throws CryptoInitializationException Thrown if the crypto libraries could not be initialized.
   * @throws KeyChainException Thrown if there is trouble managing keys.
   */
  public InputStream getMacInputStream(InputStream stream, Entity entity)
      throws IOException, KeyChainException, CryptoInitializationException {
    return mMac.demacFrom(stream, entity);
  }
}
