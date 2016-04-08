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
 * Implements GCM cipher.
 * Uses unpadded GCM (128-bits key + 96-bits IV). It includes final AAD.
 * This is the default implementation up to Conceal 1.0.6 (Conceal.getCrypto(KeyChain)).
 */
public class CryptoAlgoGcm implements CryptoAlgo {

    private final NativeCryptoLibrary mNativeLibrary;
    private final KeyChain mKeyChain;
    private final CryptoConfig mConfig;

    public CryptoAlgoGcm(NativeCryptoLibrary mNativeLibrary, KeyChain mKeyChain, CryptoConfig config) {
        this.mNativeLibrary = mNativeLibrary;
        this.mKeyChain = mKeyChain;
        this.mConfig = config;
    }

    @Override
    public OutputStream wrap(OutputStream cipherStream, Entity entity, byte[] buffer)
            throws IOException, CryptoInitializationException, KeyChainException {
        cipherStream.write(VersionCodes.CIPHER_SERIALIZATION_VERSION);
        cipherStream.write(mConfig.cipherId);

        byte[] iv = mKeyChain.getNewIV();
        NativeGCMCipher gcmCipher = new NativeGCMCipher(mNativeLibrary);
        gcmCipher.encryptInit(mKeyChain.getCipherKey(), iv);
        cipherStream.write(iv);

        byte[] entityBytes = entity.getBytes();
        computeCipherAad(gcmCipher, VersionCodes.CIPHER_SERIALIZATION_VERSION, mConfig.cipherId, entityBytes);
        return new NativeGCMCipherOutputStream(cipherStream, gcmCipher, buffer, mConfig.tagLength);
    }

    @Override
    public InputStream wrap(InputStream is, Entity entity)
            throws IOException, CryptoInitializationException, KeyChainException {
        byte cryptoVersion = (byte) is.read();
        byte cipherID = (byte) is.read();

        Assertions.checkArgumentForIO(cryptoVersion == VersionCodes.CIPHER_SERIALIZATION_VERSION,
                "Unexpected crypto version " + cryptoVersion);

        Assertions.checkArgumentForIO(cipherID == mConfig.cipherId,
                "Unexpected cipher ID " + cipherID);

        byte[] iv = new byte[mConfig.ivLength];
        // if iv is not fully read EOFException will be thrown
        new DataInputStream(is).readFully(iv);

        NativeGCMCipher gcmCipher = new NativeGCMCipher(mNativeLibrary);
        gcmCipher.decryptInit(mKeyChain.getCipherKey(), iv);

        byte[] entityBytes = entity.getBytes();
        computeCipherAad(gcmCipher, cryptoVersion, cipherID, entityBytes);
        return new NativeGCMCipherInputStream(is, gcmCipher, mConfig.tagLength);
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

    @Override
    public int getCipherMetaDataLength() {
        return 2 + mConfig.ivLength + mConfig.tagLength;
    }
}
