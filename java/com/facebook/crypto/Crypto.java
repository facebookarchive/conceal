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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import com.facebook.crypto.exception.KeyChainException;
import com.facebook.crypto.mac.NativeMac;
import com.facebook.crypto.streams.*;
import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.keychain.KeyChain;
import com.facebook.crypto.util.Assertions;
import com.facebook.crypto.util.NativeCryptoLibrary;

public class Crypto {

  private final KeyChain mKeyChain;
  private final NativeCryptoLibrary mNativeCryptoLibrary;
  private final CipherHelper mCipherHelper;

  public Crypto(KeyChain keyChain, NativeCryptoLibrary nativeCryptoLibrary) {
    mKeyChain = keyChain;
    mNativeCryptoLibrary = nativeCryptoLibrary;
    mCipherHelper = new CipherHelper(mKeyChain, mNativeCryptoLibrary);
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
    return mCipherHelper.getCipherOutputStream(cipherStream, entity);
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
    byte cryptoVersion = (byte) cipherStream.read();
    byte cipherID = (byte) cipherStream.read();

    return mCipherHelper.getCipherInputStream(cipherStream, entity, cryptoVersion, cipherID);
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
   */
  public byte[] encrypt(byte[] plainTextBytes, Entity entity)
    throws KeyChainException, CryptoInitializationException, IOException {
    int cipheredBytesLength = plainTextBytes.length + mCipherHelper.getCipherMetaDataLength();
    LeakyByteArrayOutputStream outputStream = new LeakyByteArrayOutputStream(cipheredBytesLength);
    OutputStream cipherStream = mCipherHelper.getCipherOutputStream(outputStream, entity);
    cipherStream.write(plainTextBytes);
    cipherStream.close();
    return outputStream.getBytes();
  }

  /**
   * A convenience method to decrypt data if the data to be processed is small and can
   * be held in memory.
   * @param cipherTextBytes Bytes of the cipher text.
   * @param entity Entity to process.
   * @return cipherText.
   * @throws KeyChainException
   * @throws CryptoInitializationException
   * @throws IOException
   */
  public byte[] decrypt(byte[] cipherTextBytes, Entity entity)
    throws KeyChainException, CryptoInitializationException, IOException {
    byte cryptoVersion = cipherTextBytes[0];
    byte cipherID = cipherTextBytes[1];

    int cipherTextLength = cipherTextBytes.length;
    ByteArrayInputStream cipheredStream = new ByteArrayInputStream(cipherTextBytes, 2, cipherTextLength);
    InputStream plainTextStream = mCipherHelper.getCipherInputStream(cipheredStream, entity, cryptoVersion, cipherID);

    int plainTextLength = cipherTextLength - mCipherHelper.getCipherMetaDataLength();
    LeakyByteArrayOutputStream output = new LeakyByteArrayOutputStream(plainTextLength);
    byte[] buffer = new byte[1024];
    int read;
    while ((read = plainTextStream.read(buffer)) != -1) {
      output.write(buffer, 0, read);
    }
    plainTextStream.close();
    return output.getBytes();
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
    stream.write(VersionCodes.MAC_SERIALIZATION_VERSION);
    stream.write(VersionCodes.MAC_ID);

    NativeMac nativeMac = new NativeMac(mNativeCryptoLibrary);
    byte[] macKey = mKeyChain.getMacKey();
    nativeMac.init(macKey, macKey.length);
    byte[] entityBytes = entity.getBytes();
    computeMacAad(nativeMac, VersionCodes.CIPHER_SERALIZATION_VERSION, VersionCodes.CIPHER_ID, entityBytes);
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
    byte macVersion = (byte) stream.read();
    Assertions.checkArgumentForIO(macVersion == VersionCodes.MAC_SERIALIZATION_VERSION,
        "Unexpected mac version " + macVersion);

    byte macID = (byte) stream.read();
    Assertions.checkArgumentForIO(macID == VersionCodes.MAC_ID,
        "Unexpected mac ID " + macID);

    NativeMac nativeMac = new NativeMac(mNativeCryptoLibrary);
    byte[] macKey = mKeyChain.getMacKey();
    nativeMac.init(macKey, macKey.length);

    byte[] entityBytes = entity.getBytes();
    computeMacAad(nativeMac, macVersion, VersionCodes.MAC_ID, entityBytes);
    return new NativeMacLayeredInputStream(nativeMac, stream);
  }

  /**
   * Computes the authenticated data for the mac.
   */
  private static void computeMacAad(NativeMac mac, byte macVersion, byte macID, byte[] entityBytes) throws IOException {
    byte[] cryptoVersionBytes = { macVersion };
    byte[] macIDBytes = { macID };
    mac.update(cryptoVersionBytes, 0, 1);
    mac.update(macIDBytes, 0, 1);
    mac.update(entityBytes, 0, entityBytes.length);
  }
}
