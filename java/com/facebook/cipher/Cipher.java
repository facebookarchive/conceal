// Copyright 2004-present Facebook. All Rights Reserved.

package com.facebook.cipher;

import java.io.DataInputStream;
import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

import com.facebook.cipher.jni.CipherHybrid;
import com.facebook.cipher.jni.DecryptHybrid;
import com.facebook.cipher.jni.EncryptHybrid;

import com.facebook.crypto.CheckedKeyChain;
import com.facebook.crypto.CryptoConfig;
import com.facebook.crypto.Entity;
import com.facebook.crypto.exception.KeyChainException;
import com.facebook.crypto.keychain.KeyChain;
import com.facebook.crypto.streams.TailInputStream;
import com.facebook.crypto.util.NativeCryptoLibrary;

import com.facebook.crypto.exception.CryptoInitializationException;

/**
 * New implementation of Crypto that only implements Gcm not Mac.
 * This will be the replacement for open-source Crypto when Mac
 * is just another Crypto algorithm object.
 * For now just an object, at some point there will be a general
 * interface.
 */
public class Cipher {

  /**
   * If a buffer is not provided a new byte[128] will be created for that purpose.
   * This is the same size used in old implementation of Conceal, to avoid using too much memory.
   * Although it's recommended to provide a better-suited buffer on each case.
   */
  private static final int DEFAULT_ENCRYPT_BUFFER_SIZE = 128;

  private final NativeCryptoLibrary mNativeCryptoLibrary;
  private final CryptoConfig mConfig;
  private final KeyChain mKeyChain;

  public Cipher(NativeCryptoLibrary nativeCryptoLibrary, CryptoConfig config, KeyChain keyChain) {
    mNativeCryptoLibrary = nativeCryptoLibrary;
    mConfig = config;
    mKeyChain = new CheckedKeyChain(keyChain, config);
  }

  /**
   * Wraps an output stream to write encrypted content into it.
   * This method deprecates @link{#getCipherOutputStream}.
   * @param cipherStream the stream that will receive the encrypted content
   * @param entity the entity to authenticate the content (an  tag will be included on close)
   * @param buffer an auxiliar buffer used on write. If null a default one will be created.
   *               It's recommended to provide a buffer, because the default one is small and could
   *               provoke write fragmentation.
   */
  public OutputStream encryptTo(OutputStream cipherStream, Entity entity, byte[] buffer)
          throws IOException, CryptoInitializationException {
    // CipherHybrid doesn't auto-load native code
    mNativeCryptoLibrary.ensureCryptoLoaded();
    CipherHybrid cipherHybrid = new CipherHybrid(mConfig.cipherId, mKeyChain);
    byte[] entityBytes = entity.getBytes();
    EncryptHybrid encryptHybrid = cipherHybrid.createEncrypt(entityBytes, 0, entityBytes.length);
    cipherStream.write(encryptHybrid.start());
    if (buffer == null) {
      buffer = new byte[DEFAULT_ENCRYPT_BUFFER_SIZE];
    }
    return new EncryptStream(encryptHybrid, cipherStream, buffer);
  }

  private static class EncryptStream extends FilterOutputStream {
    private final EncryptHybrid mEncryptHybrid;
    private final byte[] mBuffer;
    public EncryptStream(EncryptHybrid encryptHybrid, OutputStream out, byte[] buffer) {
      super(out);
      mEncryptHybrid = encryptHybrid;
      mBuffer = buffer;
    }
    @Override
    public void write(byte[] data, int offset, int count) throws IOException {
      int remainder = count;
      while (remainder > 0) {
        int chunkSize = Math.min(remainder, mBuffer.length);
        mEncryptHybrid.write(data, offset, mBuffer, 0, chunkSize);
        out.write(mBuffer, 0, chunkSize);
        offset += chunkSize;
        remainder -= chunkSize;
      }
    }
    @Override
    public void close() throws IOException {
      out.write(mEncryptHybrid.end());
      out.close();
    }
  }

  /**
   * Returns an InputStream that automatically decrypts from another stream.
   * This methods deprecates @link{#getCipherInputStream}.
   * @param inputStream the stream containing Conceal-encrypted content
   * @param entity the entity used to authenticate the content (it will be verified at EOS)
   */
  public InputStream decryptFrom(InputStream inputStream, Entity entity)
      throws IOException, CryptoInitializationException {
    // CipherHybrid doesn't auto-load native code
    mNativeCryptoLibrary.ensureCryptoLoaded();
    CipherHybrid cipherHybrid = new CipherHybrid(mConfig.cipherId, mKeyChain);
    byte[] entityBytes = entity.getBytes();
    DecryptHybrid decryptHybrid = cipherHybrid.createDecrypt(entityBytes, 0, entityBytes.length);
    byte[] header = new byte[mConfig.getHeaderLength()];
    new DataInputStream(inputStream).readFully(header);
    decryptHybrid.start(header);
    return new DecryptStream(decryptHybrid, inputStream, mConfig);
  }

  private static class DecryptStream extends FilterInputStream {
    private final DecryptHybrid mDecryptHybrid;
    private boolean mTagChecked;
    public DecryptStream(DecryptHybrid decryptHybrid, InputStream in, CryptoConfig config) {
      super(new TailInputStream(in, config.getTailLength()));
      mDecryptHybrid = decryptHybrid;
    }

    @Override
    public int read() throws IOException {
      throw new UnsupportedOperationException();
    }

    @Override
    public int read(byte[] buffer, int offset, int count) throws IOException {
      int result = in.read(buffer, offset, count);
      if (result < 0) {
        checkTag();
      } else {
        mDecryptHybrid.read(buffer, offset, buffer, offset, result);
      }
      return result;
    }

    @Override
    public void close() throws IOException {
      in.close();
      checkTag();
    }

    private void checkTag() throws IOException {
      if (!mTagChecked) {
        TailInputStream tailStream = (TailInputStream) in;
        boolean ok = mDecryptHybrid.end(tailStream.getTail());
        mTagChecked = true;
        if (!ok) {
          throw new IntegrityException();
        }
      }
    }
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
    // CipherHybrid doesn't auto-load native code
    mNativeCryptoLibrary.ensureCryptoLoaded();
    byte[] result = new byte[plainTextBytes.length + getCipherMetaDataLength()];
    CipherHybrid cipherHybrid = new CipherHybrid(mConfig.cipherId, mKeyChain);
    byte[] entityBytes = entity.getBytes();
    EncryptHybrid encryptHybrid = cipherHybrid.createEncrypt(entityBytes, 0, entityBytes.length);
    byte[] header = encryptHybrid.start();
    System.arraycopy(header, 0, result, 0, header.length);
    encryptHybrid.write(plainTextBytes, 0, result, header.length, plainTextBytes.length);
    byte[] tail = encryptHybrid.end();
    System.arraycopy(tail, 0, result, result.length - tail.length, tail.length);
    return result;
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
    // CipherHybrid doesn't auto-load native code
    mNativeCryptoLibrary.ensureCryptoLoaded();
    byte[] result = new byte[cipherTextBytes.length - getCipherMetaDataLength()];
    CipherHybrid cipherHybrid = new CipherHybrid(mConfig.cipherId, mKeyChain);
    byte[] entityBytes = entity.getBytes();
    DecryptHybrid decryptHybrid = cipherHybrid.createDecrypt(entityBytes, 0, entityBytes.length);
    byte[] header = Arrays.copyOfRange(cipherTextBytes, 0, mConfig.getHeaderLength());
    decryptHybrid.start(header);
    decryptHybrid.read(cipherTextBytes, header.length, result, 0, result.length);
    byte[] tail = Arrays.copyOfRange(
        cipherTextBytes,
        header.length + result.length,
        cipherTextBytes.length);
    boolean ok = decryptHybrid.end(tail);
    if (!ok) {
      throw new IntegrityException();
    }
    return result;
  }

  /**
   * Gets the length of the meta data for the version of the API being decrypted.
   * This should preserve the following invariant:
   * </p>
   * Ciphertext data size = Plaintext data + Cipher meta data.
   */
  /* package protected */ int getCipherMetaDataLength() {
    return mConfig.getHeaderLength() + mConfig.getTailLength();
  }
}
