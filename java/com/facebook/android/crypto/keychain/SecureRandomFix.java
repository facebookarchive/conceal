/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.android.crypto.keychain;

import android.os.Process;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;

import android.os.Build;
import android.os.Process;

import com.facebook.crypto.exception.KeyChainException;

/**
 * SecureRandom is not really random in android and are biased:
 * http://android-developers.blogspot.com/2013/08/some-securerandom-thoughts.html.
 * The following code is copied from the above source with some modifications.
 * <p>
 * We rely on SecureRandom to generate cryptographically secure random numbers for
 * various applications. This applies the fix suggested in the blog post which is
 * seeding random number generators for jellybean, and using /dev/urandom for pre
 * jellybean systems.
 */

public class SecureRandomFix {
  private static final int VERSION_CODE_JELLY_BEAN = 17;
  private static final int VERSION_CODE_JELLY_BEAN_MR2 = 18;
  private static final String DEV_URANDOM = "/dev/urandom";

  private static final Object sFixLock = new Object();
  private static boolean sFixApplied;

  private static final LinuxPRNGSecureRandomProvider sProvider =
      new LinuxPRNGSecureRandomProvider();

  private SecureRandomFix() {
  }

  public static SecureRandom createLocalSecureRandom() {
    if ((Build.VERSION.SDK_INT >= VERSION_CODE_JELLY_BEAN)
        && (Build.VERSION.SDK_INT <= VERSION_CODE_JELLY_BEAN_MR2)) {
      synchronized (sFixLock) {
        if (!sFixApplied) {
          tryApplyOpenSSLFix();
          sFixApplied = true;
        }
      }
    }
    if (Build.VERSION.SDK_INT <= VERSION_CODE_JELLY_BEAN_MR2) {
      // should use linux provider
      return new LocalSecureRandom();
    }
    // no special PRNG needed
    return new SecureRandom();
  }

  /**
   * This should be the only SecureRandom used around (if version <= JBMR2).
   */
  public static class LocalSecureRandom extends SecureRandom {
    private LocalSecureRandom() {
      super(new LinuxPRNGSecureRandom(), sProvider);
    }
  }

  private static void tryApplyOpenSSLFix() {
    try {
      // Mix in the device- and invocation-specific seed.
      Class.forName("org.apache.harmony.xnet.provider.jsse.NativeCrypto")
          .getMethod("RAND_seed", byte[].class)
          .invoke(null, generateSeed());

      // Mix output of Linux PRNG into OpenSSL's PRNG
      int bytesRead = (Integer) Class.forName(
          "org.apache.harmony.xnet.provider.jsse.NativeCrypto")
          .getMethod("RAND_load_file", String.class, long.class)
          .invoke(null, DEV_URANDOM, 1024);
      if (bytesRead != 1024) {
        throw new IOException(
            "Unexpected number of bytes read from Linux PRNG: "
                + bytesRead);
      }
    } catch (Exception e) {
      throw new SecurityException("Failed to seed OpenSSL PRNG", e);
    }
  }

  /**
   * Generates a device- and invocation-specific seed to be mixed into the
   * Linux PRNG.
   */
  private static byte[] generateSeed() {
    try {
      ByteArrayOutputStream seedBuffer = new ByteArrayOutputStream();
      DataOutputStream seedBufferOut =
          new DataOutputStream(seedBuffer);
      seedBufferOut.writeLong(System.currentTimeMillis());
      seedBufferOut.writeLong(System.nanoTime());
      seedBufferOut.writeInt(Process.myPid());
      seedBufferOut.writeInt(Process.myUid());
      seedBufferOut.write(getBuildFingerprintAndDeviceSerial());
      seedBufferOut.close();
      return seedBuffer.toByteArray();
    } catch (IOException e) {
      throw new SecurityException("Failed to generate seed", e);
    }
  }

  private static byte[] getBuildFingerprintAndDeviceSerial() {
    StringBuilder result = new StringBuilder();
    String fingerprint = Build.FINGERPRINT;
    if (fingerprint != null) {
      result.append(fingerprint);
    }
    String serial = getDeviceSerialNumber();
    if (serial != null) {
      result.append(serial);
    }
    try {
      return result.toString().getBytes("UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException("UTF-8 encoding not supported");
    }
  }

  /**
   * Gets the hardware serial number of this device.
   *
   * @return serial number or {@code null} if not available.
   */
  private static String getDeviceSerialNumber() {
    // We're using the Reflection API because Build.SERIAL is only available
    // since API Level 9 (Gingerbread, Android 2.3).
    try {
      return (String) Build.class.getField("SERIAL").get(null);
    } catch (Exception ignored) {
      return null;
    }
  }

  /**
   * {@code Provider} of {@code SecureRandom} engines which pass through
   * all requests to the Linux PRNG.
   */
  private static class LinuxPRNGSecureRandomProvider extends Provider {

    public LinuxPRNGSecureRandomProvider() {
      super("LinuxPRNG",
          1.0,
          "A Linux-specific random number provider that uses "
              + DEV_URANDOM);
      // Although /dev/urandom is not a SHA-1 PRNG, some apps
      // explicitly request a SHA1PRNG SecureRandom and we thus need to
      // prevent them from getting the default implementation whose output
      // may have low entropy.
      put("SecureRandom.SHA1PRNG", LinuxPRNGSecureRandom.class.getName());
      put("SecureRandom.SHA1PRNG ImplementedIn", "Software");
    }
  }

  /**
   * {@link SecureRandomSpi} which passes all requests to the Linux PRNG
   * ({@code /dev/urandom}).
   */
  public static class LinuxPRNGSecureRandom extends SecureRandomSpi {

        /*
         * IMPLEMENTATION NOTE: Requests to generate bytes and to mix in a seed
         * are passed through to the Linux PRNG (/dev/urandom). Instances of
         * this class seed themselves by mixing in the current time, PID, UID,
         * build fingerprint, and hardware serial number (where available) into
         * Linux PRNG.
         *
         * Concurrency: Read requests to the underlying Linux PRNG are
         * serialized (on sLock) to ensure that multiple threads do not get
         * duplicated PRNG output.
         */

    private static final File URANDOM_FILE = new File(DEV_URANDOM);

    private static final Object sLock = new Object();

    /**
     * Input stream for reading from Linux PRNG or {@code null} if not yet
     * opened.
     *
     * @GuardedBy("sLock")
     */
    private static DataInputStream sUrandomIn;

    /**
     * Output stream for writing to Linux PRNG or {@code null} if not yet
     * opened.
     *
     * @GuardedBy("sLock")
     */
    private static OutputStream sUrandomOut;

    /**
     * Whether this engine instance has tried to seed /dev/urandom.
     */
    private boolean mSeedAttempted;

    @Override
    protected void engineSetSeed(byte[] bytes) {
      try {
        OutputStream out;
        synchronized (sLock) {
          out = getUrandomOutputStream();
        }
        out.write(bytes);
        out.flush();
      } catch (Throwable t) {
        // Do nothing here. This can fail on Samsung devices and other devices
        // where /dev/urandom is not writable probably due to SELinux policies.
        // discussion here: https://plus.google.com/+AndroidDevelopers/posts/YxWzeNQMJS2
        // Although it is good practise to seed it with more entropy,
        // /dev/urandom should already be seeded.
      } finally {
        mSeedAttempted = true;
      }
    }

    @Override
    protected void engineNextBytes(byte[] bytes) {
      if (!mSeedAttempted) {
        // Mix in the device- and invocation-specific seed.
        engineSetSeed(generateSeed());
      }

      try {
        DataInputStream in;
        synchronized (sLock) {
          in = getUrandomInputStream();
        }
        synchronized (in) {
          in.readFully(bytes);
        }
      } catch (IOException e) {
        throw new SecurityException(
            "Failed to read from " + URANDOM_FILE, e);
      }
    }

    @Override
    protected byte[] engineGenerateSeed(int size) {
      byte[] seed = new byte[size];
      engineNextBytes(seed);
      return seed;
    }

    private DataInputStream getUrandomInputStream() {
      synchronized (sLock) {
        if (sUrandomIn == null) {
          // NOTE: Consider inserting a BufferedInputStream between
          // DataInputStream and FileInputStream if you need higher
          // PRNG output performance and can live with future PRNG
          // output being pulled into this process prematurely.
          try {
            sUrandomIn = new DataInputStream(
                new FileInputStream(URANDOM_FILE));
          } catch (IOException e) {
            throw new SecurityException("Failed to open "
                + URANDOM_FILE + " for reading", e);
          }
        }
        return sUrandomIn;
      }
    }

    private OutputStream getUrandomOutputStream() {
      synchronized (sLock) {
        if (sUrandomOut == null) {
          try {
            sUrandomOut = new FileOutputStream(URANDOM_FILE);
          } catch (IOException e) {
            throw new SecurityException("Failed to open "
                + URANDOM_FILE + " for writing", e);
          }
        }
        return sUrandomOut;
      }
    }
  }
}
