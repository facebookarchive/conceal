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
import java.io.InputStream;

/**
 * This class is used to encapsulate decryption using GCM. On reads, bytes are first read from the
 * delegate input stream and decrypted before being store in the read buffer.
 */
public class NativeGCMCipherInputStream extends InputStream {

  private static final int SKIP_BUFFER_SIZE = 256;

  private final TailInputStream mCipherDelegate;
  private final NativeGCMCipher mCipher;

  private byte[] mSkipBuffer;

  private boolean mTagChecked = false;

  /**
   * Creates a new input stream to read from.
   *
   * @param cipherDelegate The stream to read encrypted bytes from.
   * @param cipher The cipher used to decrypt the bytes.
   */
  public NativeGCMCipherInputStream(InputStream cipherDelegate, NativeGCMCipher cipher, int tagLength) {
    mCipherDelegate = new TailInputStream(cipherDelegate, tagLength);
    mCipher = cipher;
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

    read = mCipher.update(buffer, offset, read, buffer, offset);

    return read;
  }

  private void ensureTagValid() throws IOException {
    if (mTagChecked) {
      return;
    }

    // sets it to true before executing it, since we put the cipher into a finalized
    // state and destroy it, so we should not execute this again.
    mTagChecked = true;
    try {
      byte[] tail = mCipherDelegate.getTail();
      mCipher.decryptFinal(tail, tail.length);
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
    if (mSkipBuffer == null) {
      mSkipBuffer = new byte[SKIP_BUFFER_SIZE];
    }
    // implements skip through reading
    // decryption needs to process all the data anyway
    // only marginal optimization would be avoiding jni to copy back plain bytes
    // but that's only a problem for android that copies bytes instead of sharing
    long skipped = 0;

    while (byteCount > 0) {
      int chunk = (int) Math.min(byteCount, SKIP_BUFFER_SIZE);
      int read = read(mSkipBuffer, 0, chunk);
      if (read < 0) {
        break;
      }
      skipped += read;
      byteCount -= read;
    }
    // if it didn't skip anything it's EOF
    return skipped == 0 ? -1 : skipped;
  }
}
