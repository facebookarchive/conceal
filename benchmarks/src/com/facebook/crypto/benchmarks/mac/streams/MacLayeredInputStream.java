/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto.benchmarks.mac.streams;

import javax.crypto.Mac;
import java.io.IOException;
import java.io.InputStream;

public class MacLayeredInputStream extends InputStream {

  private Mac mMac;
  private InputStream mIs;

  public MacLayeredInputStream(Mac mac, InputStream is) {
    mMac = mac;
    mIs = is;
  }

  @Override
  public int available() throws IOException {
    return mIs.available();
  }

  @Override
  public void close() throws IOException {
    mIs.close();
  }

  @Override
  public void mark(int readlimit) {
    mIs.mark(readlimit);
  }

  @Override
  public boolean markSupported() {
    return mIs.markSupported();
  }

  @Override
  public int read() throws IOException {
    int read = mIs.read();
    if (read != -1) {
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
    int read = mIs.read(buffer, offset, length);
    if (read != -1) {
      mMac.update(buffer, offset, read);
    }
    return read;
  }

  @Override
  public synchronized void reset() throws IOException {
    mIs.reset();
  }

  @Override
  public long skip(long byteCount) throws IOException {
    return mIs.skip(byteCount);
  }
}
