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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * Helper functions for tests to serialize and de-serialize crypto data.
 */
public class CryptoSerializerHelper {

  public static byte[] cipherText(byte[] cipheredData) {
    return Arrays.copyOfRange(cipheredData,
        CryptoConfig.KEY_128.ivLength + 2,
        cipheredData.length - CryptoConfig.KEY_128.tagLength);
  }

  public static byte[] tag(byte[] cipheredData) {
    return Arrays.copyOfRange(cipheredData,
        cipheredData.length - CryptoConfig.KEY_128.tagLength,
        cipheredData.length);
  }

  public static byte[] createCipheredData(byte[] iv, byte[] cipherText, byte[] tag) throws IOException {
    ByteArrayOutputStream cipheredData = new ByteArrayOutputStream();
    cipheredData.write(VersionCodes.CIPHER_SERIALIZATION_VERSION);
    cipheredData.write(CryptoConfig.KEY_128.cipherId);
    cipheredData.write(iv);
    cipheredData.write(cipherText);
    cipheredData.write(tag);
    return cipheredData.toByteArray();
  }

  public static byte[] createMacData(byte[] data, byte[] macBytes) throws IOException {
    ByteArrayOutputStream dataWithMac = new ByteArrayOutputStream();
    dataWithMac.write(VersionCodes.MAC_SERIALIZATION_VERSION);
    dataWithMac.write(VersionCodes.MAC_ID);
    dataWithMac.write(data);
    dataWithMac.write(macBytes);
    return  dataWithMac.toByteArray();
  }

  public static byte[] getMacTag(byte[] macData, int macLength) {
    return Arrays.copyOfRange(macData, macData.length - macLength, macData.length);
  }

  public static byte[] getOriginalDataFromMacData(byte[] macData, int macLength) {
    return Arrays.copyOfRange(macData, 2, macData.length - macLength);
  }

  /**
   * This method mixes in the crypto serialization version as well as the ID of either the cipher or mac
   * into the authenticated bytes to prevent cross-protocol attacks, i.e. if we don't authenticate
   * this data, we could be forced to use a construction using the parameters of some other
   * construction.
   */
  public static byte[] computeBytesToAuthenticate(byte[] entityBytes, byte cryptoVersion, byte cryptoId) {
    int entityLength = entityBytes.length;
    byte[] aadBytes = new byte[entityLength + 2];
    aadBytes[0] = cryptoVersion;
    aadBytes[1] = cryptoId;
    System.arraycopy(entityBytes, 0, aadBytes, 2, entityLength);
    return aadBytes;
  }
}
