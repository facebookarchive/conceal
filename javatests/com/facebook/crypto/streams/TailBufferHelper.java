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

import java.util.Arrays;

import org.junit.Assert;

public class TailBufferHelper {

  /**
   * Verifies that the data and the tail observed match the original data.
   * @param originalData The original data that was sent to the tail buffer.
   * @param readData The data read minus the tail.
   * @param tail Tail obtained after processing via the tail buffer.
   * @param tailLength Expected length of the tail buffer.
   */
  public static void verifyDataAndTailMatch(byte[] originalData,
      byte[] readData,
      byte[] tail,
      int tailLength) {
    Assert.assertArrayEquals(
        Arrays.copyOfRange(originalData, 0, originalData.length - tailLength),
        readData);
    Assert.assertArrayEquals(
        Arrays.copyOfRange(originalData, originalData.length - tailLength, originalData.length),
        tail);
  }
}
