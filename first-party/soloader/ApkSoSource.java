// Copyright 2004-present Facebook. All Rights Reserved.

package com.facebook.soloader;

import java.io.File;
import java.io.IOException;
import android.content.Context;
import android.os.Parcel;
import android.util.Log;
import java.util.zip.ZipEntry;

/**
 * {@link SoSource} that extracts libraries from an APK to the filesystem.
 */
public class ApkSoSource extends ExtractFromZipSoSource {

  private static final String TAG = "ApkSoSource";

  /**
   * If this flag is given, do not extract libraries that appear to be correctly extracted to the
   * application libs directory.
   */
  public static final int PREFER_ANDROID_LIBS_DIRECTORY = (1<<0);

  private static final byte APK_SO_SOURCE_SIGNATURE_VERSION = 1;
  private static final byte LIBS_DIR_DONT_CARE = 0;
  private static final byte LIBS_DIR_DOESNT_EXIST = 1;
  private static final byte LIBS_DIR_SNAPSHOT = 2;

  private final int mFlags;

  public ApkSoSource(Context context, String name, int flags) {
    super(
        context,
        name,
        new File(context.getApplicationInfo().sourceDir),
        // The regular expression matches libraries that would ordinarily be unpacked
        // during installation.
        "^lib/([^/]+)/([^/]+\\.so)$");
    mFlags = flags;
  }

  @Override
  protected Unpacker makeUnpacker() throws IOException {
    return new ApkUnpacker(this);
  }

  protected class ApkUnpacker extends ZipUnpacker {

    private File mLibDir;
    private final int mFlags;

    ApkUnpacker(ExtractFromZipSoSource soSource) throws IOException {
      super(soSource);
      mLibDir = new File(mContext.getApplicationInfo().nativeLibraryDir);
      mFlags = ApkSoSource.this.mFlags;
    }

    @Override
    protected boolean shouldExtract(ZipEntry ze, String soName) {
      String zipPath = ze.getName();
      if ((mFlags & PREFER_ANDROID_LIBS_DIRECTORY) == 0) {
        Log.d(TAG, "allowing consideration of " + zipPath + ": self-extraction preferred");
        return true;
      }

      File sysLibFile = new File(mLibDir, soName);
      if (!sysLibFile.isFile()) {
        Log.d(
            TAG,
            String.format(
                "allowing considering of %s: %s not in system lib dir",
                zipPath,
                soName));
        return true;
      }

      long sysLibLength = sysLibFile.length();
      long apkLibLength = ze.getSize();

      if (sysLibLength != apkLibLength) {
        Log.d(
            TAG,
            String.format(
                "allowing consideration of %s: sysdir file length is %s, but " +
                "the file is %s bytes long in the APK",
                sysLibFile,
                sysLibLength,
                apkLibLength));
        return true;
      }

      Log.d(TAG, "not allowing consideration of " + zipPath + ": deferring to libdir");
      return false;
    }
  }

  @Override
  protected byte[] getDepsBlock() throws IOException {
    File apkFile = mZipFileName.getCanonicalFile();
    Parcel parcel = Parcel.obtain();
    try {
      parcel.writeByte(APK_SO_SOURCE_SIGNATURE_VERSION);
      parcel.writeString(apkFile.getPath());
      parcel.writeLong(apkFile.lastModified());

      if ((mFlags & PREFER_ANDROID_LIBS_DIRECTORY) == 0) {
        parcel.writeByte(LIBS_DIR_DONT_CARE);
        return parcel.marshall();
      }

      String nativeLibraryDir = mContext.getApplicationInfo().nativeLibraryDir;
      if (nativeLibraryDir == null) {
        parcel.writeByte(LIBS_DIR_DOESNT_EXIST);
        return parcel.marshall();
      }

      File canonicalFile = new File(nativeLibraryDir).getCanonicalFile();
      if (!canonicalFile.exists()) {
          parcel.writeByte(LIBS_DIR_DOESNT_EXIST);
          return parcel.marshall();
      }

      parcel.writeByte(LIBS_DIR_SNAPSHOT);
      parcel.writeString(canonicalFile.getPath());
      parcel.writeLong(canonicalFile.lastModified());
      return parcel.marshall();
    } finally {
      parcel.recycle();
    }
  }
}
