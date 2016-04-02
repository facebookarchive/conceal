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
 * Implements version 1 of cipher.
 * Uses unpadded GCM (128-bits key + 96-bits IV).
 * It includes final AAD.
 * This is the default implementation up to Conceal 1.0.5 (Conceal.getCrypto(KeyChain)).
 */
public class CryptoAlgoV1 implements CryptoAlgo {

    private final NativeCryptoLibrary mNativeLibrary;
    private final KeyChain mKeyChain;

    public CryptoAlgoV1(NativeCryptoLibrary mNativeLibrary, KeyChain mKeyChain) {
        this.mNativeLibrary = mNativeLibrary;
        this.mKeyChain = mKeyChain;
    }

    @Override
    public OutputStream wrap(OutputStream cipherStream, Entity entity, byte[] buffer)
            throws IOException, CryptoInitializationException, KeyChainException {
        cipherStream.write(VersionCodes.CIPHER_SERIALIZATION_VERSION);
        cipherStream.write(VersionCodes.CIPHER_ID);

        byte[] iv = mKeyChain.getNewIV();
        NativeGCMCipher gcmCipher = new NativeGCMCipher(mNativeLibrary);
        gcmCipher.encryptInit(mKeyChain.getCipherKey(), iv);
        cipherStream.write(iv);

        byte[] entityBytes = entity.getBytes();
        computeCipherAad(gcmCipher, VersionCodes.CIPHER_SERIALIZATION_VERSION, VersionCodes.CIPHER_ID, entityBytes);
        return new NativeGCMCipherOutputStream(cipherStream, gcmCipher, buffer);
    }

    @Override
    public InputStream wrap(InputStream is, Entity entity)
            throws IOException, CryptoInitializationException, KeyChainException {
        byte cryptoVersion = (byte) is.read();
        byte cipherID = (byte) is.read();

        Assertions.checkArgumentForIO(cryptoVersion == VersionCodes.CIPHER_SERIALIZATION_VERSION,
                "Unexpected crypto version " + cryptoVersion);

        Assertions.checkArgumentForIO(cipherID == VersionCodes.CIPHER_ID,
                "Unexpected cipher ID " + cipherID);

        byte[] iv = new byte[NativeGCMCipher.IV_LENGTH];
        // if iv is not fully read EOFException will be thrown
        new DataInputStream(is).readFully(iv);

        NativeGCMCipher gcmCipher = new NativeGCMCipher(mNativeLibrary);
        gcmCipher.decryptInit(mKeyChain.getCipherKey(), iv);

        byte[] entityBytes = entity.getBytes();
        computeCipherAad(gcmCipher, cryptoVersion, cipherID, entityBytes);
        return new NativeGCMCipherInputStream(is, gcmCipher);
    }

    /**
     * Computes the Aad data for the cipher.
     */
    private void computeCipherAad(NativeGCMCipher gcmCipher, byte cryptoVersion, byte cipherID, byte[] entityBytes)
            throws NativeGCMCipherException {
        byte[] cryptoVersionBytes = { cryptoVersion };
        byte[] cipherIDBytes = { cipherID };
        gcmCipher.updateAad(cryptoVersionBytes, 1);
        gcmCipher.updateAad(cipherIDBytes, 1);
        gcmCipher.updateAad(entityBytes, entityBytes.length);
    }

}
