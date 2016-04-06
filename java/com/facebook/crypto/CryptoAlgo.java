package com.facebook.crypto;

import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.exception.KeyChainException;
import com.facebook.crypto.keychain.KeyChain;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Represents the algorithm used to encrypt/decrypt a stream.
 * When wrapping the stream it writes/reads the header, version information, IV data and
 * returns a stream ready to write/read plain data.
 * Different version of the cipher will implement this interface, while client code will always
 * use Crypto which contains all the utility methods and is a common entry point.
 */
public interface CryptoAlgo {
    OutputStream wrap(OutputStream os, Entity entity, byte[] buffer)
            throws IOException, CryptoInitializationException, KeyChainException;
    InputStream wrap(InputStream is, Entity entity)
            throws IOException, CryptoInitializationException, KeyChainException;
    int getCipherMetaDataLength();
}
