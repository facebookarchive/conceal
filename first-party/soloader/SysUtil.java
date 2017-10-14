/**
 * Copyright (c) 2015-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. An additional grant
 * of patent rights can be found in the PATENTS file in the same directory.
 */

package com.facebook.soloader;

import java.io.File;
import java.io.IOException;
import android.content.Context;

import java.util.jar.JarFile;
import java.util.jar.JarEntry;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

import android.os.Build;
import android.system.Os;
import android.system.ErrnoException;
import android.system.OsConstants;

import java.util.HashMap;
import java.util.Map;
import java.util.Enumeration;

import java.io.InputStream;
import java.io.FileOutputStream;
import java.io.FileDescriptor;
import java.io.RandomAccessFile;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Parcel;

public final class SysUtil {

  private static final byte APK_SIGNATURE_VERSION = 1;

  /**
   * Determine how preferred a given ABI is on this system.
   *
   * @param supportedAbis ABIs on this system
   * @param abi ABI of a shared library we might want to unpack
   * @return -1 if not supported or an integer, smaller being more preferred
   */
  public static int findAbiScore(String[] supportedAbis, String abi) {
    for (int i = 0; i < supportedAbis.length; ++i) {
      if (supportedAbis[i] != null && abi.equals(supportedAbis[i])) {
        return i;
      }
    }

    return -1;
  }

  public static void deleteOrThrow(File file) throws IOException {
    if (!file.delete()) {
      throw new IOException("could not delete file " + file);
    }
  }

  /**
   * Return an list of ABIs we supported on this device ordered according to preference.  Use a
   * separate inner class to isolate the version-dependent call where it won't cause the whole
   * class to fail preverification.
   *
   * @return Ordered array of supported ABIs
   */
  public static String[] getSupportedAbis() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
      return new String[]{Build.CPU_ABI, Build.CPU_ABI2};
    } else {
      return LollipopSysdeps.getSupportedAbis();
    }
  }

  /**
   * Pre-allocate disk space for a file if we can do that
   * on this version of the OS.
   *
   * @param fd File descriptor for file
   * @param length Number of bytes to allocate.
   */
  public static void fallocateIfSupported(FileDescriptor fd, long length) throws IOException {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
      LollipopSysdeps.fallocateIfSupported(fd, length);
    }
  }

  /**
   * Delete a directory and its contents.
   *
   * WARNING: Java APIs do not let us distinguish directories from symbolic links to directories.
   * Consequently, if the directory contains symbolic links to directories, we will attempt to
   * delete the contents of pointed-to directories.
   *
   * @param file File or directory to delete
   */
  public static void dumbDeleteRecursive(File file) throws IOException {
    if (file.isDirectory()) {
      File[] fileList = file.listFiles();
      if (fileList == null) {
        // If file is not a directory, listFiles() will return null
        return;
      }
      for (File entry : fileList) {
        dumbDeleteRecursive(entry);
      }
    }

    if (!file.delete() && file.exists()) {
      throw new IOException("could not delete: " + file);
    }
  }

  /**
   * Encapsulate Lollipop-specific calls into an independent class so we don't fail preverification
   * downlevel.
   */
  private static final class LollipopSysdeps {
    @DoNotOptimize
    public static String[] getSupportedAbis() {
      return Build.SUPPORTED_ABIS;
    }

    @DoNotOptimize
    public static void fallocateIfSupported(FileDescriptor fd, long length) throws IOException {
      try {
        Os.posix_fallocate(fd, 0, length);
      } catch (ErrnoException ex) {
        if (ex.errno != OsConstants.EOPNOTSUPP &&
            ex.errno != OsConstants.ENOSYS &&
            ex.errno != OsConstants.EINVAL) {
          throw new IOException(ex.toString(), ex);
        }
      }
    }
  }

  /**
   * Like File.mkdirs, but throws on error.  Succeeds even if
   * File.mkdirs "fails", but dir still names a directory.
   *
   * @param dir Directory to create.  All parents created as well.
   */
  static void mkdirOrThrow(File dir) throws IOException {
    if (!dir.mkdirs() && !dir.isDirectory()) {
      throw new IOException("cannot mkdir: " + dir);
    }
  }

  /**
   * Copy up to byteLimit bytes from the input stream to the output stream.
   *
   * @param os Destination stream
   * @param is Input stream
   * @param byteLimit Maximum number of bytes to copy
   * @param buffer IO buffer to use
   * @return Number of bytes actually copied
   */
  static int copyBytes(RandomAccessFile os, InputStream is, int byteLimit, byte[] buffer)
      throws IOException {
    // Yes, this method is exactly the same as the above, just with a different type for `os'.
    int bytesCopied = 0;
    int nrRead;
    while (bytesCopied < byteLimit &&
        (nrRead = is.read(
            buffer,
            0,
            Math.min(buffer.length, byteLimit - bytesCopied))) != -1) {
      os.write(buffer, 0, nrRead);
      bytesCopied += nrRead;
    }
    return bytesCopied;
  }

  static void fsyncRecursive(File fileName) throws IOException {
    if (fileName.isDirectory()) {
      File[] files = fileName.listFiles();
      if (files == null) {
        throw new IOException("cannot list directory " + fileName);
      }
      for (int i = 0; i < files.length; ++i) {
        fsyncRecursive(files[i]);
      }
    } else if (fileName.getPath().endsWith("_lock")) {
      /* Do not sync! Any close(2) of a locked file counts as releasing the file for the whole
       * process! */
    } else {
      try (RandomAccessFile file = new RandomAccessFile(fileName, "r")) {
        file.getFD().sync();
      }
    }
  }

  public static byte[] makeApkDepBlock(File apkFile, Context context) throws IOException {
    apkFile = apkFile.getCanonicalFile();
    Parcel parcel = Parcel.obtain();
    try {
      parcel.writeByte(APK_SIGNATURE_VERSION);
      parcel.writeString(apkFile.getPath());
      parcel.writeLong(apkFile.lastModified());
      parcel.writeInt(getAppVersionCode(context));
      return parcel.marshall();
    } finally {
      parcel.recycle();
    }
  }

  public static int getAppVersionCode(Context context) {
    final PackageManager pm = context.getPackageManager();
    if (pm != null) {
      try {
        PackageInfo pi = pm.getPackageInfo(context.getPackageName(), 0);
        return pi.versionCode;
      } catch (PackageManager.NameNotFoundException e) {
        // That should not happen
      } catch (RuntimeException e) {
          // To catch RuntimeException("Package manager has died") that can occur
          // on some version of Android, when the remote PackageManager is
          // unavailable. I suspect this sometimes occurs when the App is being reinstalled.
      }
    }
    return 0;
  }
}
