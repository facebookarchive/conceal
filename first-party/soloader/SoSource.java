/**
 * Copyright (c) 2015-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. An additional grant
 * of patent rights can be found in the PATENTS file in the same directory.
 */

package com.facebook.soloader;

import javax.annotation.Nullable;

import java.io.File;
import java.io.IOException;
import java.util.Collection;

abstract public class SoSource {

  /**
   * This SoSource doesn't know how to provide the given library.
   */
  public static final int LOAD_RESULT_NOT_FOUND = 0;

  /**
   * This SoSource loaded the given library.
   */
  public static final int LOAD_RESULT_LOADED = 1;

  /**
   * This SoSource did not load the library, but verified that the system loader will load it if
   * some other library depends on it.  Returned only if LOAD_FLAG_ALLOW_IMPLICIT_PROVISION is
   * provided to loadLibrary.
   */
  public static final int LOAD_RESULT_IMPLICITLY_PROVIDED = 2;

  /**
   * Allow loadLibrary to implicitly provide the library instead of actually loading it.
   */
  public static final int LOAD_FLAG_ALLOW_IMPLICIT_PROVISION = 1;

  /**
   * Min flag that can be used in customized {@link SoFileLoader#load(String, int)}
   * implementation. The custom flag value has to be greater than this.
   */
  public static final int LOAD_FLAG_MIN_CUSTOM_FLAG = 1 << 1;

  /**
   * Allow prepare to spawn threads to do background work.
   */
  public static final int PREPARE_FLAG_ALLOW_ASYNC_INIT = (1<<0);

  /**
   * Prepare to install this SoSource in SoLoader.
   */
  protected void prepare(int flags) throws IOException {
    /* By default, do nothing */
  }

  /**
   * Load a shared library library into this process.  This routine is independent of
   * {@link #loadLibrary}.
   *
   * @param soName Name of library to load
   * @param loadFlags Zero or more of the LOAD_FLAG_XXX constants.
   * @return One of the LOAD_RESULT_XXX constants.
   */
  abstract public int loadLibrary(String soName, int loadFlags) throws IOException;

  /**
   * Ensure that a shared library exists on disk somewhere.  This routine is independent of
   * {@link #loadLibrary}.
   *
   * @param soName Name of library to load
   * @return File if library found; {@code null} if not.
   */
  @Nullable
  abstract public File unpackLibrary(String soName) throws IOException;

  /**
   * Add an element to an LD_LIBRARY_PATH under construction.
   *
   * @param paths Collection of paths to which to add
   */
  public void addToLdLibraryPath(Collection<String> paths) {
    /* By default, do nothing */
  }

  /**
   * Return an array of ABIs handled by this SoSource.
   *
   * @return ABIs supported by this SoSource
   */
  public String[] getSoSourceAbis() {
    /* By default, the same as the device */
    return SysUtil.getSupportedAbis();
  }
}
