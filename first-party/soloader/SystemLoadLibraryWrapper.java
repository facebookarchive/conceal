// Copyright 2004-present Facebook. All Rights Reserved.

package com.facebook.soloader;

/**
 * @see SoLoader#setSystemLoadLibraryWrapper
 */
public interface SystemLoadLibraryWrapper {
  void loadLibrary(String libName);
}
