/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto;

import java.io.UnsupportedEncodingException;

/**
 * Use this object to keep track of the data you are encrypting/decrypting. Every piece of data
 * being encrypted should have a unique entity identifying what that data is.
 *
 * This is used for an authenticity check i.e. to ensure that when you read from the input stream,
 * you are actually reading the data you expect to be reading. If the entity differs between the
 * output and input streams, decryption will fail.
 */
public class Entity {

  private String mName;

  /**
   * Creates an Entity object.
   *
   * @param name The name of the 'entity' you expect to be performing operations on.
   */
  public Entity(String name) {
    this.mName = name;
  }

  public byte[] getBytes() throws UnsupportedEncodingException {
    return mName.getBytes("UTF-16");
  }
}
