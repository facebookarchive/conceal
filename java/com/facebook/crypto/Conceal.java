package com.facebook.crypto;

import com.facebook.crypto.keychain.KeyChain;
import com.facebook.crypto.keygen.PasswordBasedKeyDerivation;
import com.facebook.crypto.util.NativeCryptoLibrary;
import com.facebook.crypto.util.SystemNativeCryptoLibrary;

import java.security.SecureRandom;

/**
 * Factory class to create cryptographic components.
 * It's configured with the support components to use:
 * <ul>
 * <li>native library loader</li>
 * <li>random number generator</li>
 * </ul>
 * For Android please use {@link com.facebook.android.crypto.AndroidConceal}.
 * @see com.facebook.android.crypto.AndroidConceal#get()
 */
public abstract class Conceal {

    public final NativeCryptoLibrary nativeLibrary;
    public final SecureRandom secureRandom;

    protected Conceal(NativeCryptoLibrary nativeLibrary, SecureRandom secureRandom) {
        this.nativeLibrary = nativeLibrary;
        this.secureRandom = secureRandom;
    }

    public Crypto createCrypto(KeyChain keyChain) {
        return new Crypto(keyChain, this.nativeLibrary);
    }

    public PasswordBasedKeyDerivation createPasswordBasedKeyDerivation() {
        return new PasswordBasedKeyDerivation(secureRandom, nativeLibrary);
    }
}
