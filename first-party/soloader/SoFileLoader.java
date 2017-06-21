// Copyright 2004-present Facebook. All Rights Reserved.

package com.facebook.soloader;

public interface SoFileLoader {

  /**
   * Load the so file from given path.
   */
  void load(String pathToSoFile, int loadFlags);
}
