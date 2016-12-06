/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.android.crypto.keychain;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import com.facebook.crypto.CryptoConfig;
import com.facebook.crypto.exception.KeyChainException;
import com.facebook.crypto.keychain.KeyChain;
import com.facebook.crypto.mac.NativeMac;

import java.security.SecureRandom;
import java.util.Arrays;

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

  private final CryptoConfig mCryptoConfig;

  private final SharedPreferences mSharedPreferences;
  private final SecureRandom mSecureRandom;

  protected byte[] mCipherKey;
  protected boolean mSetCipherKey;

  protected byte[] mMacKey;
  protected boolean mSetMacKey;

  /**
   * @deprecated This default constructor uses 128-bit keys for backward compatibility
   *             but current standard is 256-bits. Use explicit constructor instead.
   */
  @Deprecated
  public SharedPrefsBackedKeyChain(Context context) {
    this(context, CryptoConfig.KEY_128);
  }

  public SharedPrefsBackedKeyChain(Context context, CryptoConfig config) {
    String prefName = prefNameForConfig(config);
    mSharedPreferences = context.getSharedPreferences(prefName, Context.MODE_PRIVATE);
    mSecureRandom = SecureRandomFix.createLocalSecureRandom();
    mCryptoConfig = config;
  }

  /**
   * We should store different configuration keys separately, specially to support the
   * case of migration: one KeyChain has the 128-bit to read old stored data, another KeyChain
   * has the 256-bit value to rewrite all data.
   * <p>
   * So the preference name will depend on the config.
   * For backward compatibility the name for 128-bits is kept as SHARED_PREF_NAME.
   */
  private static String prefNameForConfig(CryptoConfig config) {
    return config == CryptoConfig.KEY_128
            ? SHARED_PREF_NAME
            : SHARED_PREF_NAME + "." + String.valueOf(config);

  }

  @Override
  public synchronized byte[] getCipherKey() throws KeyChainException {
    if (!mSetCipherKey) {
      mCipherKey = maybeGenerateKey(CIPHER_KEY_PREF, mCryptoConfig.keyLength);
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
    byte[] iv = new byte[mCryptoConfig.ivLength];
    mSecureRandom.nextBytes(iv);
    return iv;
  }

  @Override
  public synchronized void destroyKeys() {
    mSetCipherKey = false;
    mSetMacKey = false;
    if (mCipherKey != null) {
      Arrays.fill(mCipherKey, (byte) 0);
    }
    if (mMacKey != null) {
      Arrays.fill(mMacKey, (byte) 0);
    }
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
