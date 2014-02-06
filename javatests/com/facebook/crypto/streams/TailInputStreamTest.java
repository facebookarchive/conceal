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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Random;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class TailInputStreamTest {

  private TailInputStream mTailInputStream;
  private InputStream mInputStream;
  private byte[] mInputData;

  private final int TAIL_LENGTH = 16;

  @Before
  public void setUp() {
    mInputData = new byte[TAIL_LENGTH * 20 + 7];
    Random random = new Random();
    random.nextBytes(mInputData);
    mInputStream = new ByteArrayInputStream(mInputData);
    mTailInputStream = new TailInputStream(mInputStream, TAIL_LENGTH);
  }

  @Test
  public void testReadInSmallIncrements() throws IOException {
    byte[] temp = new byte[TAIL_LENGTH / 3];
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    readFully(mTailInputStream, temp, outputStream);
    byte[] tail = mTailInputStream.getTail();
    byte[] readData = outputStream.toByteArray();
    TailBufferHelper.verifyDataAndTailMatch(mInputData, readData, tail, TAIL_LENGTH);
  }

  @Test
  public void testReadInTagSizeIncrements() throws IOException {
    byte[] temp = new byte[TAIL_LENGTH];
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    readFully(mTailInputStream, temp, outputStream);
    byte[] tail = mTailInputStream.getTail();
    byte[] readData = outputStream.toByteArray();
    TailBufferHelper.verifyDataAndTailMatch(mInputData, readData, tail, TAIL_LENGTH);
  }

  @Test
  public void testReadInLargeIncrements() throws IOException {
    byte[] temp = new byte[TAIL_LENGTH * 2 + 3];
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    readFully(mTailInputStream, temp, outputStream);
    byte[] tail = mTailInputStream.getTail();
    byte[] readData = outputStream.toByteArray();
    TailBufferHelper.verifyDataAndTailMatch(mInputData, readData, tail, TAIL_LENGTH);
  }

  @Test
  public void testReadOneByteAtATime() throws IOException {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    int read;
    while ((read = mTailInputStream.read()) != -1) {
      outputStream.write(read);
    }
    byte[] tail = mTailInputStream.getTail();
    byte[] readData = outputStream.toByteArray();
    TailBufferHelper.verifyDataAndTailMatch(mInputData, readData, tail, TAIL_LENGTH);
  }

  @Test(expected = IOException.class)
  public void throwsWhenTailNotSufficient() throws IOException {
    byte[] data = new byte[TAIL_LENGTH - 1];
    TailInputStream tailStream =
        new TailInputStream(new ByteArrayInputStream(data), TAIL_LENGTH);
    byte[] temp = new byte[TAIL_LENGTH * 2 + 3];
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    readFully(tailStream, temp, outputStream);
    tailStream.getTail();
  }

  @Test
  public void testBytesReturnedByUnderlyingStreamIsReduced() throws IOException {
    InputStream inputStream = new ByteReducingInputStream(mInputStream, 2);
    TailInputStream tailInputStream =
        new TailInputStream(inputStream, TAIL_LENGTH);
    byte[] temp = new byte[TAIL_LENGTH * 2 + 3];
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    readFully(tailInputStream, temp, outputStream);
    byte[] tail = tailInputStream.getTail();
    byte[] readData = outputStream.toByteArray();
    TailBufferHelper.verifyDataAndTailMatch(mInputData, readData, tail, TAIL_LENGTH);
  }

  private void readFully(InputStream input,
      byte[] tempBuffer,
      ByteArrayOutputStream output) throws IOException {
    int read = 0;
    while ((read = input.read(tempBuffer)) != -1) {
      Assert.assertTrue(read > 0);
      output.write(tempBuffer, 0, read);
    }
  }

  private static class ByteReducingInputStream extends FilterInputStream {

    private final float mReduction;

    protected ByteReducingInputStream(InputStream in, float reduction) {
      super(in);
      mReduction = reduction;
    }

    public int read(byte[] buffer, int offset, int count) throws IOException {
      int newCount = (int) ((float) count / mReduction);
      return in.read(buffer, offset, newCount);
    }
  }
}
