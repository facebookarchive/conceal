/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto.util;

import java.io.IOException;

/**
 * Adaptation of certain methods required by us so that we don't have
 * to introduce a dependency on guava.
 */
public class Assertions {

  public static void checkState(boolean expression, String errorMessage) {
    if (!expression) {
      throw new IllegalStateException(String.valueOf(errorMessage));
    }
  }

  public static void checkArgumentForIO(boolean expression, String errorMessage) throws IOException {
    if (!expression) {
      throw new IOException(errorMessage);
    }
  }
}
