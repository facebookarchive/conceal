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

import java.io.IOException;
import java.io.InputStream;

import com.facebook.crypto.cipher.NativeGCMCipher;

/**
 * This class is used to encapsulate decryption using GCM. On reads, bytes are first read from the
 * delegate input stream and decrypted before being store in the read buffer.
 */
public class NativeGCMCipherInputStream extends InputStream {

  private static final int UPDATE_BUFFER_SIZE = 256;

  private final TailInputStream mCipherDelegate;
  private final NativeGCMCipher mCipher;

  private final byte[] mUpdateBuffer;

  private boolean mTagChecked = false;

  /**
   * Creates a new input stream to read from.
   *
   * @param cipherDelegate The stream to read encrypted bytes from.
   * @param cipher The cipher used to decrypt the bytes.
   */
  public NativeGCMCipherInputStream(InputStream cipherDelegate, NativeGCMCipher cipher) {
    mCipherDelegate = new TailInputStream(cipherDelegate, NativeGCMCipher.TAG_LENGTH);
    mCipher = cipher;
    mUpdateBuffer = new byte[UPDATE_BUFFER_SIZE + mCipher.getCipherBlockSize()];
  }

  @Override
  public int available() throws IOException {
    return mCipherDelegate.available();
  }

  @Override
  public void close() throws IOException {
    try {
      ensureTagValid();
    } finally {
      mCipherDelegate.close();
    }
  }

  @Override
  public void mark(int readlimit) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean markSupported() {
    return false;
  }

  @Override
  public int read() throws IOException {
    throw new UnsupportedOperationException();
  }

  @Override
  public int read(byte[] buffer) throws IOException {
    return read(buffer, 0, buffer.length);
  }

  @Override
  public int read(byte[] buffer, int offset, int length)
      throws IOException {
    if (buffer.length < offset + length) {
      throw new ArrayIndexOutOfBoundsException(offset + length);
    }

    int read = mCipherDelegate.read(buffer, offset, length);

    if (read == -1) {
      // since we have reached the end of the input stream we should
      // verify whether the tag of the data we've read in is valid.
      ensureTagValid();
      return -1;
    }

    int times = read / UPDATE_BUFFER_SIZE;
    int remainder = read % UPDATE_BUFFER_SIZE;

    int originalOffset = offset;
    int currentReadOffset = offset;

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

    return currentReadOffset - originalOffset;
  }

  private void ensureTagValid() throws IOException {
    if (mTagChecked) {
      return;
    }

    // sets it to true before executing it, since we put the cipher into a finalized
    // state and destroy it, so we should not execute this again.
    mTagChecked = true;
    try {
      mCipher.decryptFinal(mCipherDelegate.getTail(), NativeGCMCipher.TAG_LENGTH);
    } finally {
      mCipher.destroy();
    }
  }

  @Override
  public synchronized void reset() throws IOException {
    throw new UnsupportedOperationException();
  }

  @Override
  public long skip(long byteCount) throws IOException {
    throw new UnsupportedOperationException();
  }
}
