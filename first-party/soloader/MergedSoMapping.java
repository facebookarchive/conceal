// Copyright 2004-present Facebook. All Rights Reserved.

package com.facebook.soloader;

class MergedSoMapping {
  static String mapLibName(String preMergedLibName) {
    return null;
  }

  static void invokeJniOnload(String preMergedLibName) {
    throw new IllegalArgumentException(
        "Unknown library: " + preMergedLibName);
  }
}
