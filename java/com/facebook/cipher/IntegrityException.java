// Copyright 2004-present Facebook. All Rights Reserved.

package com.facebook.cipher;

import java.io.IOException;

/**
 * Represents an error on verifying the integrity of a
 * message being deciphered. Be it decrypting or reading
 * a mac'd text.
 */
public class IntegrityException extends IOException {

private static final String DEFAULT_MESSAGE =
    "The message could not be decrypted successfully." +
    "It has either been tampered with or the wrong resource is being decrypted.";

  public IntegrityException() {
    super(DEFAULT_MESSAGE);
  }

  public IntegrityException(String message) {
    super(message);
  }
}
