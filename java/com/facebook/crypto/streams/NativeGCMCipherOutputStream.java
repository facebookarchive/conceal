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

import com.facebook.crypto.cipher.NativeGCMCipher;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.ArrayIndexOutOfBoundsException;

/**
 * This class is used to encapsulate encryption using GCM. On writes, bytes are first encrypted
 * before actually being written out to the delegate stream.
 */
public class NativeGCMCipherOutputStream extends OutputStream {

  private static final int UPDATE_BUFFER_SIZE = 256;

  private final OutputStream mCipherDelegate;
  private final NativeGCMCipher mCipher;
  private final byte[] mUpdateBuffer;
  private final byte[] mTag = new byte[NativeGCMCipher.TAG_LENGTH];

  /**
   * Creates a new output stream to write to.
   *
   * @param cipherDelegate The stream to write encrypted bytes to.
   * @param cipher The cipher used to encrypt the bytes.
   */
  public NativeGCMCipherOutputStream(OutputStream cipherDelegate,
      NativeGCMCipher cipher) {
    mCipherDelegate = cipherDelegate;
    mCipher = cipher;
    mUpdateBuffer = new byte[UPDATE_BUFFER_SIZE + mCipher.getCipherBlockSize()];
  }

  @Override
  public void close() throws IOException {
    try {
      mCipher.encryptFinal(mTag, mTag.length);
      mCipherDelegate.write(mTag);
    } finally {
      try {
        mCipher.destroy();
      } finally {
        mCipherDelegate.close();
      }
    }
  }

  @Override
  public void flush() throws IOException {
    mCipherDelegate.flush();
  }

  @Override
  public void write(byte[] buffer) throws IOException {
    write(buffer, 0, buffer.length);
  }

  @Override
  public void write(byte[] buffer, int offset, int count)
      throws IOException {
    if (buffer.length < offset + count) {
      throw new ArrayIndexOutOfBoundsException(offset + count);
    }

    int times = count / UPDATE_BUFFER_SIZE;
    int remainder = count % UPDATE_BUFFER_SIZE;

    for (int i = 0; i < times; ++i) {
      int written = mCipher.update(buffer, offset, UPDATE_BUFFER_SIZE, mUpdateBuffer);
      mCipherDelegate.write(mUpdateBuffer, 0, written);
      offset += UPDATE_BUFFER_SIZE;
    }

    if (remainder > 0) {
      int written = mCipher.update(buffer, offset, remainder, mUpdateBuffer);
      mCipherDelegate.write(mUpdateBuffer, 0, written);
    }
  }

  @Override
  public void write(int oneByte) throws IOException {
    throw new UnsupportedOperationException();
  }
}
