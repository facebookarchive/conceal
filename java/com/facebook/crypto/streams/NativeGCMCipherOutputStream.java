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

  private static final int DEFAULT_ENCRYPT_BUFFER_SIZE = 256;

  private final OutputStream mCipherDelegate;
  private final NativeGCMCipher mCipher;
  private final int mUpdateBufferChunkSize;
  private final byte[] mUpdateBuffer;
  private final byte[] mTag = new byte[NativeGCMCipher.TAG_LENGTH];

  private boolean mTagAppended = false;

  /**
   * Creates a new output stream to write to.
   *
   * @param cipherDelegate The stream to write encrypted bytes to.
   * @param cipher The cipher used to encrypt the bytes.
   */
  public NativeGCMCipherOutputStream(
          OutputStream cipherDelegate,
          NativeGCMCipher cipher,
          byte[] encryptBuffer) {
    mCipherDelegate = cipherDelegate;
    mCipher = cipher;

    // use encryptBuffer or create a new one
    int cipherBlockSize = mCipher.getCipherBlockSize();
    if (encryptBuffer == null) {
      encryptBuffer = new byte[DEFAULT_ENCRYPT_BUFFER_SIZE + cipherBlockSize];
    } else {
      int minSize = cipherBlockSize + 1;
      if (encryptBuffer.length < minSize) {
        throw new IllegalArgumentException("encryptBuffer cannot be smaller than " + minSize + "B");
      }
    }
    // if no encryptBuffer provided it will be DEFAULT_ENCRYPT_BUFFER_SIZE
    mUpdateBufferChunkSize = encryptBuffer.length - cipherBlockSize;
    mUpdateBuffer = encryptBuffer;
  }

  @Override
  public void close() throws IOException {
    try {
      appendTag();
    } finally {
      mCipherDelegate.close();
    }
  }

  private void appendTag() throws IOException {
    if (mTagAppended) {
      return;
    }
    mTagAppended = true;
    try {
      mCipher.encryptFinal(mTag, mTag.length);
      mCipherDelegate.write(mTag);
    } finally {
      mCipher.destroy();
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

    int times = count / mUpdateBufferChunkSize;
    int remainder = count % mUpdateBufferChunkSize;

    for (int i = 0; i < times; ++i) {
      int written = mCipher.update(buffer, offset, mUpdateBufferChunkSize, mUpdateBuffer, 0);
      mCipherDelegate.write(mUpdateBuffer, 0, written);
      offset += mUpdateBufferChunkSize;
    }

    if (remainder > 0) {
      int written = mCipher.update(buffer, offset, remainder, mUpdateBuffer, 0);
      mCipherDelegate.write(mUpdateBuffer, 0, written);
    }
  }

  @Override
  public void write(int oneByte) throws IOException {
    byte[] data = new byte[1];
    data[0] = (byte) oneByte;
    write(data, 0, 1);
  }
}
