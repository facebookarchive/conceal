package com.facebook.crypto.streams;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * A byte array stream which tries to avoid the double copy of
 * bytes when calling {@link java.io.ByteArrayOutputStream#toByteArray()}
 */
public class LeakyByteArrayOutputStream extends ByteArrayOutputStream {

  /**
   * @param size Size for the underlying byte array. You should pass in
   *             the exact size of the array you need.
   */
  public LeakyByteArrayOutputStream(int size) {
    super(size);
  }

  public byte[] getBytes() throws IOException {
    if (buf.length != count) {
      // This should not happen since we explicitly set the size
      // in such a way that the size will be perfect.
      throw new IOException("Size supplied is too small");
    }
    return buf;
  }
}
