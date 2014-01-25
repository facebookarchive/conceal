/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto.keychain;

import java.security.SecureRandom;
import java.util.Arrays;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import com.facebook.crypto.cipher.NativeGCMCipher;
import com.facebook.crypto.exception.KeyChainException;
import com.facebook.crypto.mac.NativeMac;

/**
 * An implementation of a keychain that is backed by shared preferences.
 * </p>
 * The implementation tries to cache results as much as possible to avoid
 * having to do expensive lookups to shared preferences. The keys are generated
 * lazily on first use.
 * </p>
 * If your code is sensitive to running shared preference I/O operations on the
 * UI thread, consider calling {@link #getCipherKey()} off the main thread, or
 * providing your own implementation similar to this class using a different
 * backing store.
 */
public class SharedPrefsBackedKeyChain implements KeyChain {

  // Visible for testing.
  /* package */ static final String SHARED_PREF_NAME = "crypto";
  /* package */ static final String CIPHER_KEY_PREF = "cipher_key";
  /* package */ static final String MAC_KEY_PREF = "mac_key";

  private final SharedPreferences mSharedPreferences;
  private final SecureRandom mSecureRandom;

  protected byte[] mCipherKey;
  protected boolean mSetCipherKey;

  protected byte[] mMacKey;
  protected boolean mSetMacKey;

  private static final SecureRandomFix sSecureRandomFix = new SecureRandomFix();

  public SharedPrefsBackedKeyChain(Context context) {
    mSharedPreferences = context.getSharedPreferences(SHARED_PREF_NAME, Context.MODE_PRIVATE);
    mSecureRandom = new SecureRandom();
  }

  @Override
  public synchronized byte[] getCipherKey() throws KeyChainException {
    if (!mSetCipherKey) {
      mCipherKey = maybeGenerateKey(CIPHER_KEY_PREF, NativeGCMCipher.KEY_LENGTH);
    }
    mSetCipherKey = true;
    return mCipherKey;
  }

  @Override
  public byte[] getMacKey() throws KeyChainException {
    if (!mSetMacKey) {
      mMacKey = maybeGenerateKey(MAC_KEY_PREF, NativeMac.KEY_LENGTH);
    }
    mSetMacKey = true;
    return mMacKey;
  }

  @Override
  public byte[] getNewIV() throws KeyChainException {
    sSecureRandomFix.tryApplyFixes();
    byte[] iv = new byte[NativeGCMCipher.IV_LENGTH];
    mSecureRandom.nextBytes(iv);
    return iv;
  }

  @Override
  public synchronized void destroyKeys() {
    mSetCipherKey = false;
    mSetMacKey = false;
    Arrays.fill(mCipherKey, (byte) 0);
    Arrays.fill(mMacKey, (byte) 0);
    mCipherKey = null;
    mMacKey = null;
    SharedPreferences.Editor editor = mSharedPreferences.edit();
    editor.remove(CIPHER_KEY_PREF);
    editor.remove(MAC_KEY_PREF);
    editor.commit();
  }

  /**
   * Generates a key associated with a preference.
   */
  private byte[] maybeGenerateKey(String pref, int length) throws KeyChainException {
    String base64Key = mSharedPreferences.getString(pref, null);
    if (base64Key == null) {
      // Generate key if it doesn't exist.
      return generateAndSaveKey(pref, length);
    } else {
      return decodeFromPrefs(base64Key);
    }
  }

  private byte[] generateAndSaveKey(String pref, int length) throws KeyChainException {
    sSecureRandomFix.tryApplyFixes();
    byte[] key = new byte[length];
    mSecureRandom.nextBytes(key);
    // Store the session key.
    SharedPreferences.Editor editor = mSharedPreferences.edit();
    editor.putString(
        pref,
        encodeForPrefs(key));
    editor.commit();
    return key;
  }

  /**
   * Visible for testing.
   */
  /* package */ byte[] decodeFromPrefs(String keyString) {
    if (keyString == null) {
      return null;
    }
    return Base64.decode(keyString, Base64.DEFAULT);
  }

  /**
   * Visible for testing.
   */
  /* package */ String encodeForPrefs(byte[] key) {
    if (key == null ) {
      return null;
    }
    return Base64.encodeToString(key, Base64.DEFAULT);
  }
}
