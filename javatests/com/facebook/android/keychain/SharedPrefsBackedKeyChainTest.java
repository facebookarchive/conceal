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

import java.util.Arrays;

import android.content.Context;
import android.content.SharedPreferences;

import com.facebook.crypto.exception.KeyChainException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import static junit.framework.Assert.*;

@RunWith(RobolectricTestRunner.class)
@Config(manifest = "javatests/com/facebook/crypto/TestAndroidManifest.xml")
public class SharedPrefsBackedKeyChainTest {

  private SharedPreferences mSharedPreferences;
  private Context mContext;

  @Before
  public void setUp() {
    mContext = Robolectric.application.getApplicationContext();
    mSharedPreferences = Robolectric.application.getSharedPreferences(
        SharedPrefsBackedKeyChain.SHARED_PREF_NAME,
        Context.MODE_PRIVATE);
  }

  @Test
  public void testKeyGeneratedOnFirstUse() throws KeyChainException {
    SharedPrefsBackedKeyChain keyChain = new SharedPrefsBackedKeyChain(mContext);
    byte[] cipherKey = keyChain.getCipherKey();
    assertNotNull(cipherKey);
    byte[] prefCipherKey = keyChain.decodeFromPrefs(
        mSharedPreferences.getString(SharedPrefsBackedKeyChain.CIPHER_KEY_PREF, null));
    assertTrue(Arrays.equals(prefCipherKey, cipherKey));

    byte[] macKey = keyChain.getMacKey();
    assertNotNull(cipherKey);
    byte[] prefMacKey = keyChain.decodeFromPrefs(
        mSharedPreferences.getString(SharedPrefsBackedKeyChain.MAC_KEY_PREF, null));
    assertTrue(Arrays.equals(prefMacKey, macKey));
  }

  @Test
  public void testSubsequentInvocationsGenerateSameKey() throws KeyChainException {
    SharedPrefsBackedKeyChain keyChain = new SharedPrefsBackedKeyChain(mContext);
    byte[] cipherKey = keyChain.getCipherKey();
    byte[] cipherKey2 = keyChain.getCipherKey();
    assertTrue(Arrays.equals(cipherKey, cipherKey2));

    byte[] macKey = keyChain.getMacKey();
    byte[] macKey2 = keyChain.getMacKey();
    assertTrue(Arrays.equals(macKey, macKey2));
  }

  @Test
  public void testDestroyCleansKeys() throws KeyChainException {
    VerifiableSharedPrefsBackedKeyChain keyChain =
        new VerifiableSharedPrefsBackedKeyChain(mContext);
    keyChain.getCipherKey();
    keyChain.getMacKey();
    keyChain.destroyKeys();

    assertFalse(keyChain.isCipherKeySet());
    assertFalse(keyChain.isMacKeySet());
    assertFalse(mSharedPreferences.contains(SharedPrefsBackedKeyChain.CIPHER_KEY_PREF));
    assertFalse(mSharedPreferences.contains(SharedPrefsBackedKeyChain.MAC_KEY_PREF));
  }

  @Test
  public void testNewKeyGeneratedAfterDestroy() throws KeyChainException {
    SharedPrefsBackedKeyChain keyChain = new SharedPrefsBackedKeyChain(mContext);
    byte[] cipherKey = keyChain.getCipherKey();
    byte[] macKey = keyChain.getMacKey();

    keyChain.destroyKeys();
    byte[] cipherKey2 = keyChain.getCipherKey();
    byte[] macKey2 = keyChain.getMacKey();

    assertNotNull(cipherKey);
    assertNotNull(cipherKey2);
    assertNotNull(macKey);
    assertNotNull(macKey2);
    assertFalse(Arrays.equals(cipherKey, cipherKey2));
    assertFalse(Arrays.equals(macKey, macKey2));
  }

  @Test
  public void testDifferentKeysGeneratedForMacAndCipher() throws KeyChainException {
    SharedPrefsBackedKeyChain keyChain = new SharedPrefsBackedKeyChain(mContext);
    byte[] cipherKey = keyChain.getCipherKey();
    byte[] macKey = keyChain.getMacKey();
    assertFalse(Arrays.equals(cipherKey, macKey));
  }

  private class VerifiableSharedPrefsBackedKeyChain extends SharedPrefsBackedKeyChain {

    public VerifiableSharedPrefsBackedKeyChain(Context context) {
      super(context);
    }

    public boolean isMacKeySet() {
      return mSetMacKey && mMacKey != null;
    }

    public boolean isCipherKeySet() {
      return mSetCipherKey && mCipherKey != null;
    }
  }
}
