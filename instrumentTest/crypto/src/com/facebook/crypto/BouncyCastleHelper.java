/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import android.annotation.TargetApi;
import android.os.Build;

import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.modes.GCMBlockCipher;
import org.spongycastle.crypto.params.AEADParameters;
import org.spongycastle.crypto.params.KeyParameter;

@TargetApi(Build.VERSION_CODES.GINGERBREAD)
public class BouncyCastleHelper {

  public static Result bouncyCastleEncrypt(byte[] data, byte[] key, byte[] iv, byte[] aadData)
      throws UnsupportedEncodingException, InvalidCipherTextException {
    GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
    byte[] gcmOut = new byte[CryptoTestUtils.NUM_DATA_BYTES + CryptoConfig.KEY_128.tagLength];
    KeyParameter keyParameter = new KeyParameter(key);

    // Add aad data.
    AEADParameters params = new AEADParameters(
          keyParameter,
          CryptoConfig.KEY_128.tagLength * 8,
          iv,
          aadData);

    // Init encryption.
    gcm.init(true, params);
    int written = gcm.processBytes(data, 0, data.length, gcmOut, 0);
    written += gcm.doFinal(gcmOut, written);

    byte[] bouncyCastleOut = Arrays.copyOfRange(gcmOut, 0, written);
    byte[] cipherText =
        Arrays.copyOfRange(bouncyCastleOut, 0, CryptoTestUtils.NUM_DATA_BYTES);
    byte[] tag =
        Arrays.copyOfRange(bouncyCastleOut, CryptoTestUtils.NUM_DATA_BYTES, bouncyCastleOut.length);
    return new Result(cipherText, tag);
  }

  public static class Result {

    public final byte[] cipherText;
    public final byte[] tag;

    public Result(byte[] cipherText, byte[] tag) {
      this.cipherText = cipherText;
      this.tag = tag;
    }
  }
}

