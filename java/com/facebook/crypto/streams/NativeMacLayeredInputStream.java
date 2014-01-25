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

import com.facebook.crypto.mac.NativeMac;

import java.io.IOException;
import java.io.InputStream;

import android.annotation.TargetApi;
import android.os.Build;

@TargetApi(Build.VERSION_CODES.GINGERBREAD)
public class NativeMacLayeredInputStream extends InputStream {

  private final NativeMac mMac;
  private final TailInputStream mInputDelegate;

  private boolean mMacChecked = false;

  private static final String MAC_DOES_NOT_MATCH = "Mac does not match";

  /**
   * Creates a new input stream to read from.
   *
   * @param mac The object used to compute the mac.
   * @param inputDelegate The stream to read the data from.
   */
  public NativeMacLayeredInputStream(NativeMac mac, InputStream inputDelegate) {
    mMac = mac;
    mInputDelegate = new TailInputStream(inputDelegate, mac.getMacLength());
  }

  @Override
  public int available() throws IOException {
    return mInputDelegate.available();
  }

  @Override
  public void close() throws IOException {
    try {
      ensureMacValid();
    } finally {
      mInputDelegate.close();
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
    int read = mInputDelegate.read();
    if (read > 0) {
      mMac.update((byte) read);
    }
    return read;
  }

  @Override
  public int read(byte[] buffer) throws IOException {
    return read(buffer, 0, buffer.length);
  }

  @Override
  public int read(byte[] buffer, int offset, int length) throws IOException {
    int read = mInputDelegate.read(buffer, offset, length);
    if (read == -1) {
      ensureMacValid();
      return -1;
    }

    if (read > 0) {
      mMac.update(buffer, offset, read);
    }

    return read;
  }

  private void ensureMacValid() throws IOException {
    if (mMacChecked) {
      return;
    }

    mMacChecked = true;
    try {
      byte[] mac = mMac.doFinal();
      if (!constantTimeEquals(mInputDelegate.getTail(), mac)) {
        throw new IOException(MAC_DOES_NOT_MATCH);
      }
    } finally {
      mMac.destroy();
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

  private boolean constantTimeEquals(byte[] a, byte[] b) {
    if (a.length != b.length) {
      return false;
    }
    int compare = 0;
    for (int i = 0; i < a.length; ++i) {
      compare |= a[i] ^ b[i];
    }
    if (compare == 0) {
      return true;
    }
    return false;
  }
}
