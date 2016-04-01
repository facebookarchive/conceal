package com.facebook.android.crypto.keychain;

import com.facebook.crypto.Conceal;
import com.facebook.crypto.util.SystemNativeCryptoLibrary;

/**
 * Conceal factory for android.
 * It sets up the right random number generator.
 */
public class AndroidConceal extends Conceal {

    private static AndroidConceal sInstance;

    public static synchronized AndroidConceal get() {
        if (sInstance == null) {
            sInstance = new AndroidConceal();
        }
        return sInstance;
    }

    private AndroidConceal() {
        super(new SystemNativeCryptoLibrary(), new FixedSecureRandom());
    }
}
