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
import java.io.OutputStream;

public class MacLayeredOutputStream extends OutputStream {

  private Mac mMac;
  private OutputStream mOs;

  public MacLayeredOutputStream(Mac mac, OutputStream os) {
    mMac = mac;
    mOs = os;
  }

  @Override
  public void close() throws IOException {
    mOs.close();
  }

  @Override
  public void flush() throws IOException {
    mOs.flush();
  }

  @Override
  public void write(byte[] buffer) throws IOException {
    write(buffer, 0, buffer.length);
  }

  @Override
  public void write(byte[] buffer, int offset, int count) throws IOException {
    mOs.write(buffer, offset, count);
    mMac.update(buffer, offset, count);
  }

  @Override
  public void write(int oneByte) throws IOException {
    mOs.write(oneByte);
    mMac.update((byte) oneByte);
  }
}
