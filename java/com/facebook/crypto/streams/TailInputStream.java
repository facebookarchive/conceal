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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * An input stream that always maintains a tail of fixed length.
 */
public class TailInputStream extends FilterInputStream {

  private final byte[] mTail;
  private final int mTailTength;

  private int mCount;
  private boolean mEOF;

  protected TailInputStream(InputStream in, int tailLength) {
    super(in);
    mTail = new byte[tailLength];
    mTailTength = tailLength;
  }

  @Override
  public int read() throws IOException {
    byte[] buffer = new byte[1];
    return read(buffer, 0, 1);
  }

  @Override
  public int read(byte[] buffer, int offset, int count) throws IOException {
    if (mEOF) {
      return -1;
    }

    if (count == 0) {
      return 0;
    }

    int read = 0;
    while (read == 0) {
      read = readTail(buffer, offset, count);
    }

    return read;
  }

  /**
   * Tries to read data from the delegate input stream into the buffer while extracting
   * a tail from it.
   */
  private int readTail(byte[] buffer, int offset, int count) throws IOException {
    if (count >= mCount) {
      int remain = count - mCount;
      int readBytes = in.read(buffer, offset + mCount, remain);
      if (readBytes == -1) {
        mEOF = true;
        return -1;
      }

      if (mCount > 0) {
        System.arraycopy(mTail, 0, buffer, offset, mCount);
      }
      int dataInBuffer = mCount + readBytes;

      int tailBytes = in.read(mTail, 0, mTailTength);

      if (tailBytes == -1) {
        mEOF = true;
        tailBytes = 0;
      }
      return extractTail(buffer, dataInBuffer, tailBytes, offset);
    } else {
      // count < mCount
      int newLength = mCount - count;
      System.arraycopy(mTail, 0, buffer, offset, count);
      System.arraycopy(mTail, count, mTail, 0, newLength);

      int tailBytes = in.read(mTail, newLength, mTailTength - newLength);

      if (tailBytes == -1) {
        // reverse the copy.
        System.arraycopy(mTail, 0, mTail, count, newLength);
        System.arraycopy(buffer, offset, mTail, 0, count);
        mEOF = true;
        return -1;
      } else {
        return extractTail(buffer, count, tailBytes + newLength, offset);
      }
    }
  }

  /**
   * Constructs the largest tail we can extract given the state of the buffers by attempting
   * to back-fill the tail buffer with bytes from the readBuffer.
   * @param readBuffer The buffer supplied by the client.
   * @param bytesInBuffer The number of bytes currently in the readBuffer.
   * @param tailBytes The number of bytes currently in the tail buffer.
   * @param bufferOffset The current offset in the readBuffer.
   * @return number of bytes read into the readBuffer.
   */
  private int extractTail(byte[] readBuffer, int bytesInBuffer, int tailBytes, int bufferOffset) {
    int toFill = mTailTength - tailBytes;
    int tailOffsetInBuffer = Math.max(0, bytesInBuffer - toFill) + bufferOffset;
    int bytesToCopy = Math.min(toFill, bytesInBuffer);

    if (bytesToCopy > 0) {
      if (tailBytes > 0) {
        System.arraycopy(mTail, 0, mTail, bytesToCopy, tailBytes);
      }
      System.arraycopy(readBuffer, tailOffsetInBuffer, mTail, 0, bytesToCopy);
    }

    mCount = bytesToCopy + tailBytes;
    return tailOffsetInBuffer - bufferOffset;
  }

  @Override
  public boolean markSupported() {
    return false;
  }

  public byte[] getTail() throws IOException {
    if (mCount != mTailTength) {
      throw new IOException("Not enough tail data");
    }
    return mTail;
  }
}
