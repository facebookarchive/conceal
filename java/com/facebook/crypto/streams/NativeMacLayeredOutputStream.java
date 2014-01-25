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
import java.io.OutputStream;

public class NativeMacLayeredOutputStream extends OutputStream {

  private final NativeMac mMac;
  private final OutputStream mOutputDelegate;

  /**
   * Creates a new output stream to write to.
   *
   * @param mac The object used to compute the mac.
   * @param outputDelegate The stream to write data to.
   */
  public NativeMacLayeredOutputStream(NativeMac mac, OutputStream outputDelegate) {
    mMac = mac;
    mOutputDelegate = outputDelegate;
  }

  @Override
  public void close() throws IOException {
    try {
      byte[] mac = mMac.doFinal();
      mOutputDelegate.write(mac);
    } finally {
      try {
        mOutputDelegate.close();
      } finally {
        mMac.destroy();
      }
    }
  }

  @Override
  public void flush() throws IOException {
    mOutputDelegate.flush();
  }

  @Override
  public void write(byte[] buffer) throws IOException {
    write(buffer, 0, buffer.length);
  }

  @Override
  public void write(byte[] buffer, int offset, int count) throws IOException {
    mOutputDelegate.write(buffer, offset, count);
    mMac.update(buffer, offset, count);
  }

  @Override
  public void write(int oneByte) throws IOException {
    mOutputDelegate.write(oneByte);
    mMac.update((byte) oneByte);
  }
}
