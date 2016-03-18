package com.facebook.crypto;

import com.facebook.crypto.cipher.NativeGCMCipher;
import com.facebook.crypto.cipher.NativeGCMCipherException;
import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.exception.KeyChainException;
import com.facebook.crypto.keychain.KeyChain;
import com.facebook.crypto.streams.NativeGCMCipherInputStream;
import com.facebook.crypto.streams.NativeGCMCipherOutputStream;
import com.facebook.crypto.util.Assertions;
import com.facebook.crypto.util.NativeCryptoLibrary;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * A helper class with common functionality required for cipher operations in {@link Crypto}.
 */
/* package */ class CipherHelper {

  private final KeyChain mKeyChain;
  private final NativeCryptoLibrary mNativeCryptoLibrary;

  public CipherHelper(KeyChain keyChain, NativeCryptoLibrary nativeCryptoLibrary) {
    mKeyChain = keyChain;
    mNativeCryptoLibrary = nativeCryptoLibrary;
  }

  public OutputStream getCipherOutputStream(OutputStream cipherStream, Entity entity, byte[] encryptBuffer)
    throws KeyChainException, CryptoInitializationException, IOException {

    cipherStream.write(VersionCodes.CIPHER_SERIALIZATION_VERSION);
    cipherStream.write(VersionCodes.CIPHER_ID);

    byte[] iv = mKeyChain.getNewIV();
    NativeGCMCipher gcmCipher = new NativeGCMCipher(mNativeCryptoLibrary);
    gcmCipher.encryptInit(mKeyChain.getCipherKey(), iv);
    cipherStream.write(iv);

    byte[] entityBytes = entity.getBytes();
    computeCipherAad(gcmCipher, VersionCodes.CIPHER_SERIALIZATION_VERSION, VersionCodes.CIPHER_ID, entityBytes);
    return new NativeGCMCipherOutputStream(cipherStream, gcmCipher, encryptBuffer);
  }

  /**
   * Returns a cipher stream for the crypto version and id.
   */
  public InputStream getCipherInputStream(InputStream cipherStream, Entity entity, byte cryptoVersion, byte cipherID)
    throws IOException, KeyChainException, CryptoInitializationException {

    Assertions.checkArgumentForIO(cryptoVersion == VersionCodes.CIPHER_SERIALIZATION_VERSION,
      "Unexpected crypto version " + cryptoVersion);

    Assertions.checkArgumentForIO(cipherID == VersionCodes.CIPHER_ID,
      "Unexpected cipher ID " + cipherID);

    byte[] iv = new byte[NativeGCMCipher.IV_LENGTH];
    // if iv is not fully read EOFException will be thrown
    new DataInputStream(cipherStream).readFully(iv);

    NativeGCMCipher gcmCipher = new NativeGCMCipher(mNativeCryptoLibrary);
    gcmCipher.decryptInit(mKeyChain.getCipherKey(), iv);

    byte[] entityBytes = entity.getBytes();
    computeCipherAad(gcmCipher, cryptoVersion, cipherID, entityBytes);
    return new NativeGCMCipherInputStream(cipherStream, gcmCipher);
  }

  /**
   * Gets the length of the meta data for the version of the API being decrypted.
   * This should preserve the following invariant:
   * </p>
   * Ciphertext data size = Plaintext data + Cipher meta data.
   */
  public int getCipherMetaDataLength() {
    return 2 + NativeGCMCipher.IV_LENGTH + NativeGCMCipher.TAG_LENGTH;
  }

  /**
   * Computes the Aad data for the cipher.
   */
  public void computeCipherAad(NativeGCMCipher gcmCipher, byte cryptoVersion, byte cipherID, byte[] entityBytes)
    throws NativeGCMCipherException {
    byte[] cryptoVersionBytes = { cryptoVersion };
    byte[] cipherIDBytes = { cipherID };
    gcmCipher.updateAad(cryptoVersionBytes, 1);
    gcmCipher.updateAad(cipherIDBytes, 1);
    gcmCipher.updateAad(entityBytes, entityBytes.length);
  }
}
