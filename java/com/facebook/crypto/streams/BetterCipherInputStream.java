/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto.streams;

import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * The Cipher stream implementation in android is really slow.
 * This provides a better cipher stream for java Ciphers.
 * </p>
 * If we ran benchmark code with the default cipher input stream in android,
 * we would beat it hands down. We use this stream so that we can have a
 * more fair comparison.
 */
public class BetterCipherInputStream extends FilterInputStream {

  private static final int UPDATE_BUFFER_SIZE = 256;

  private final Cipher mCipher;
  private final byte[] mUpdateBuffer;

  public BetterCipherInputStream(InputStream in, Cipher cipher) {
    super(in);
    mCipher = cipher;
    mUpdateBuffer = new byte[UPDATE_BUFFER_SIZE];
  }

  @Override
  public int read(byte[] buffer, int offset, int count) throws IOException {
    int read = in.read(buffer, offset, count);
    if (read == -1) {
      return -1;
    }

    int times = read / UPDATE_BUFFER_SIZE;
    int remainder = read % UPDATE_BUFFER_SIZE;

    int originalOffset = offset;
    int currentReadOffset = offset;

    try {
      for (int i = 0; i < times; ++i) {
        int bytesDecrypted = mCipher.update(buffer, offset, UPDATE_BUFFER_SIZE, mUpdateBuffer);
        System.arraycopy(mUpdateBuffer, 0, buffer, currentReadOffset, bytesDecrypted);
        currentReadOffset += bytesDecrypted;
        offset += UPDATE_BUFFER_SIZE;
      }

      if (remainder > 0) {
        int bytesDecrypted = mCipher.update(buffer, offset, remainder, mUpdateBuffer);
        System.arraycopy(mUpdateBuffer, 0, buffer, currentReadOffset, bytesDecrypted);
        currentReadOffset += bytesDecrypted;
      }
    } catch (ShortBufferException e) {
      // do nothing. This cannot happen, since we supply the correct lengths.
    }

    return currentReadOffset - originalOffset;
  }
}
