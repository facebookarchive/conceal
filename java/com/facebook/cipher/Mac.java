// Copyright 2004-present Facebook. All Rights Reserved.

package com.facebook.cipher;

import java.io.DataInputStream;
import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

import com.facebook.cipher.jni.MacDecoderHybrid;
import com.facebook.cipher.jni.MacEncoderHybrid;

import com.facebook.crypto.CheckedKeyChain;
import com.facebook.crypto.Entity;
import com.facebook.crypto.MacConfig;
import com.facebook.crypto.exception.KeyChainException;
import com.facebook.crypto.keychain.KeyChain;
import com.facebook.crypto.streams.TailInputStream;
import com.facebook.crypto.util.NativeCryptoLibrary;

import com.facebook.crypto.exception.CryptoInitializationException;

/**
 * Similar to Cipher but implements authentication without encryption (MAC).
 * For now it doesn't receive nothing like CryptoConfig (a MacConfig), and it uses the standard
 * KeyChain instead of a slimmed version that normalizes mac as a key+0IV cipher.
 * Later it will be added and the old types will be deprecated.
 */
public class Mac {

  // as there's only one MAC configuration, we declare the constants here
  private static final int MAC_HEADER = MacConfig.DEFAULT.getHeaderLength();
  private static final int MAC_TAIL = MacConfig.DEFAULT.getTailLength();

  private final NativeCryptoLibrary mNativeCryptoLibrary;
  private final KeyChain mKeyChain;

  public Mac(NativeCryptoLibrary nativeCryptoLibrary, KeyChain keyChain) {
    mNativeCryptoLibrary = nativeCryptoLibrary;
    mKeyChain = new CheckedKeyChain(keyChain, /* the CryptoConfig is only used for gcm */ null);
  }

  /**
   * Wraps an output stream to write MAC'ed content into it.
   * This method deprecates @link{Crypto#getMacOutputStream}.
   * @param cipherStream the stream that will receive the encrypted content
   * @param entity the entity to authenticate the content (an  tag will be included on close)
   */
  public OutputStream macTo(OutputStream cipherStream, Entity entity)
          throws KeyChainException, IOException, CryptoInitializationException {
    // MacEncoder/Decoder doesn't auto-load native code
    mNativeCryptoLibrary.ensureCryptoLoaded();
    byte[] entityBytes = entity.getBytes();
    MacEncoderHybrid encryptHybrid = new MacEncoderHybrid(mKeyChain.getMacKey(), entityBytes);
    cipherStream.write(encryptHybrid.start());
    return new EncryptStream(encryptHybrid, cipherStream);
  }

  private static class EncryptStream extends FilterOutputStream {
    private final MacEncoderHybrid mEncryptHybrid;
    public EncryptStream(MacEncoderHybrid encryptHybrid, OutputStream out) {
      super(out);
      mEncryptHybrid = encryptHybrid;
    }
    @Override
    public void write(byte[] data, int offset, int count) throws IOException {
      mEncryptHybrid.write(data, offset, count);
      out.write(data, offset, count);
    }
    @Override
    public void close() throws IOException {
      out.write(mEncryptHybrid.end());
      out.close();
    }
  }

  /**
   * Returns an InputStream that automatically verifies a MAC'ed stream.
   * This methods deprecates @link{Crypto#getMacInputStream}.
   * @param inputStream the stream containing Conceal-encrypted content
   * @param entity the entity used to authenticate the content (it will be verified at EOS)
   */
  public InputStream demacFrom(InputStream inputStream, Entity entity)
      throws KeyChainException, IOException, CryptoInitializationException {
    // MacEncoder/Decoder doesn't auto-load native code
    mNativeCryptoLibrary.ensureCryptoLoaded();
    byte[] entityBytes = entity.getBytes();
    MacDecoderHybrid decryptHybrid = new MacDecoderHybrid(mKeyChain.getMacKey(), entityBytes);
    byte[] header = new byte[MAC_HEADER];
    new DataInputStream(inputStream).readFully(header);
    decryptHybrid.start(header);
    return new DecryptStream(decryptHybrid, inputStream);
  }

  private static class DecryptStream extends FilterInputStream {
    private final MacDecoderHybrid mDecryptHybrid;
    private boolean mTagChecked;
    public DecryptStream(MacDecoderHybrid decryptHybrid, InputStream in) {
      super(new TailInputStream(in, MAC_TAIL));
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
        mDecryptHybrid.read(buffer, offset, result);
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
   * A convenience method to MAC data if the data to be processed is small and can
   * be held in memory.
   * @param plainTextBytes Bytes of the plain text.
   * @param entity Entity to process.
   * @return authenticated bytes.
   * @throws KeyChainException
   * @throws CryptoInitializationException
   * @throws IOException
   * @throws CryptoInitializationException Thrown if the crypto libraries could not be initialized.
   * @throws KeyChainException Thrown if there is trouble managing keys.
   */
  public byte[] mac(byte[] plainTextBytes, Entity entity)
      throws KeyChainException, CryptoInitializationException, IOException {
    // MacEncoder/Decoder doesn't auto-load native code
    mNativeCryptoLibrary.ensureCryptoLoaded();
    byte[] result = new byte[plainTextBytes.length + MAC_HEADER + MAC_TAIL];
    byte[] entityBytes = entity.getBytes();
    MacEncoderHybrid encryptHybrid = new MacEncoderHybrid(mKeyChain.getMacKey(), entityBytes);
    byte[] header = encryptHybrid.start();
    System.arraycopy(header, 0, result, 0, header.length);
    encryptHybrid.write(plainTextBytes, 0, plainTextBytes.length);
    System.arraycopy(plainTextBytes, 0, result, header.length, plainTextBytes.length);
    byte[] tail = encryptHybrid.end();
    System.arraycopy(tail, 0, result, result.length - tail.length, tail.length);
    return result;
  }

  /**
   * A convenience method to extract and verify MACed data if the data to be processed is small
   * and can be held in memory.
   * @param cipherTextBytes Bytes of the authenticated text.
   * @param entity Entity to process.
   * @return validated plain text.
   * @throws IOException
   * @throws CryptoInitializationException Thrown if the crypto libraries could not be initialized.
   * @throws KeyChainException Thrown if there is trouble managing keys.
   */
  public byte[] demac(byte[] cipherTextBytes, Entity entity)
      throws KeyChainException, CryptoInitializationException, IOException {
    // MacEncoder/Decoder doesn't auto-load native code
    mNativeCryptoLibrary.ensureCryptoLoaded();
    byte[] entityBytes = entity.getBytes();
    MacDecoderHybrid decryptHybrid = new MacDecoderHybrid(mKeyChain.getMacKey(), entityBytes);
    byte[] header = Arrays.copyOfRange(cipherTextBytes, 0, MAC_HEADER);
    decryptHybrid.start(header);
    byte[] result =
        Arrays.copyOfRange(cipherTextBytes, MAC_HEADER, cipherTextBytes.length - MAC_TAIL);
    decryptHybrid.read(result, 0, result.length);
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
}
