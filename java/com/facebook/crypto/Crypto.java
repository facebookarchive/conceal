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

import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.exception.KeyChainException;
import com.facebook.crypto.keychain.KeyChain;
import com.facebook.crypto.mac.NativeMac;
import com.facebook.crypto.streams.FixedSizeByteArrayOutputStream;
import com.facebook.crypto.streams.NativeMacLayeredInputStream;
import com.facebook.crypto.streams.NativeMacLayeredOutputStream;
import com.facebook.crypto.util.Assertions;
import com.facebook.crypto.util.NativeCryptoLibrary;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class Crypto {

  private final KeyChain mKeyChain;
  private final NativeCryptoLibrary mNativeCryptoLibrary;
  private final CryptoAlgo mCryptoAlgo;

  /**
   * @deprecated Use ConcealAndroid.get().createCrypto(...)
   */
  @Deprecated
  public Crypto(KeyChain keyChain, NativeCryptoLibrary nativeCryptoLibrary) {
    this(keyChain, nativeCryptoLibrary, CryptoConfig.KEY_128);
  }

  public Crypto(KeyChain keyChain, NativeCryptoLibrary nativeCryptoLibrary, CryptoConfig config) {
    mKeyChain = new CheckedKeyChain(keyChain, config);
    mNativeCryptoLibrary = nativeCryptoLibrary;
    mCryptoAlgo = new CryptoAlgoGcm(mNativeCryptoLibrary, mKeyChain, config);
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
   */
  public OutputStream getCipherOutputStream(OutputStream cipherStream, Entity entity)
          throws IOException, CryptoInitializationException, KeyChainException {
    return getCipherOutputStream(cipherStream, entity, null);
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
   */
  public OutputStream getCipherOutputStream(OutputStream cipherStream, Entity entity, byte[] encryptBuffer)
      throws IOException, CryptoInitializationException, KeyChainException {
    return mCryptoAlgo.wrap(cipherStream, entity, encryptBuffer);
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
    return mCryptoAlgo.wrap(cipherStream, entity);
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
    int cipheredBytesLength = plainTextBytes.length + getCipherMetaDataLength();
    FixedSizeByteArrayOutputStream outputStream = new FixedSizeByteArrayOutputStream(cipheredBytesLength);
    OutputStream cipherStream = getCipherOutputStream(outputStream, entity, null);
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
   * @throws IOException
   * @throws CryptoInitializationException Thrown if the crypto libraries could not be initialized.
   * @throws KeyChainException Thrown if there is trouble managing keys.
   */
  public byte[] decrypt(byte[] cipherTextBytes, Entity entity)
    throws KeyChainException, CryptoInitializationException, IOException {

    int cipherTextLength = cipherTextBytes.length;
    ByteArrayInputStream cipheredStream = new ByteArrayInputStream(cipherTextBytes);
    InputStream plainTextStream = getCipherInputStream(cipheredStream, entity);

    int plainTextLength = cipherTextLength - getCipherMetaDataLength();
    FixedSizeByteArrayOutputStream output = new FixedSizeByteArrayOutputStream(plainTextLength);
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
   * @throws CryptoInitializationException Thrown if the crypto libraries could not be initialized.
   * @throws KeyChainException Thrown if there is trouble managing keys.
   */
  public OutputStream getMacOutputStream(OutputStream stream, Entity entity)
      throws IOException, KeyChainException, CryptoInitializationException {
    stream.write(VersionCodes.MAC_SERIALIZATION_VERSION);
    stream.write(VersionCodes.MAC_ID);

    NativeMac nativeMac = new NativeMac(mNativeCryptoLibrary);
    byte[] macKey = mKeyChain.getMacKey();
    nativeMac.init(macKey, macKey.length);
    byte[] entityBytes = entity.getBytes();
    computeMacAad(nativeMac, VersionCodes.MAC_SERIALIZATION_VERSION, VersionCodes.MAC_ID, entityBytes);
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
   * @throws CryptoInitializationException Thrown if the crypto libraries could not be initialized.
   * @throws KeyChainException Thrown if there is trouble managing keys.
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

  /**
   * Gets the length of the meta data for the version of the API being decrypted.
   * This should preserve the following invariant:
   * </p>
   * Ciphertext data size = Plaintext data + Cipher meta data.
   */
  /* package protected */ int getCipherMetaDataLength() {
    return mCryptoAlgo.getCipherMetaDataLength();
  }
}
