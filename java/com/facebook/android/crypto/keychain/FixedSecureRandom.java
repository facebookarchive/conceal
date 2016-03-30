package com.facebook.android.crypto.keychain;

import java.security.SecureRandom;

/**
 * Child implementation of SecureRandom that runs the needed fix before generating byte arrays.
 * Client code should only use nextBytes (as it's the only method using the fix).
 * {@see SecureRandomFix}
 */
public class FixedSecureRandom extends SecureRandom {

    @Override
    public synchronized void nextBytes(byte[] bytes) {
        SecureRandomFix.tryApplyFixes();
        super.nextBytes(bytes);
    }
}
