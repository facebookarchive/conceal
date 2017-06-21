// Copyright 2004-present Facebook. All Rights Reserved.

package com.facebook.soloader;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import android.content.Context;
import java.io.RandomAccessFile;
import java.io.DataInput;
import java.io.DataOutput;
import android.util.Log;
import java.nio.channels.FileLock;
import java.util.Arrays;
import java.io.EOFException;
import java.io.File;
import java.io.Closeable;
import android.os.Parcel;

/**
 * {@link SoSource} that extracts libraries from an APK to the filesystem.
 */
public abstract class UnpackingSoSource extends DirectorySoSource {

  private static final String TAG = "fb-UnpackingSoSource";

  private static final String STATE_FILE_NAME = "dso_state";
  private static final String LOCK_FILE_NAME = "dso_lock";
  private static final String DEPS_FILE_NAME = "dso_deps";
  private static final String MANIFEST_FILE_NAME = "dso_manifest";

  private static final byte STATE_DIRTY = 0;
  private static final byte STATE_CLEAN = 1;

  private static final byte MANIFEST_VERSION = 1;

  protected final Context mContext;
  private String[] mAbis;

  protected UnpackingSoSource(Context context, String name) {
    super(getSoStorePath(context, name), RESOLVE_DEPENDENCIES);
    mContext = context;
  }

  protected UnpackingSoSource(Context context, File storePath) {
    super(storePath, RESOLVE_DEPENDENCIES);
    mContext = context;
  }

  public static File getSoStorePath(Context context, String name) {
    return new File(context.getApplicationInfo().dataDir + "/" + name);
  }

  protected abstract Unpacker makeUnpacker() throws IOException;

  @Override
  public String[] getSoSourceAbis() {
    if (mAbis == null) {
      return super.getSoSourceAbis();
    }

    return mAbis;
  }

  public void setSoSourceAbis(final String []abis) {
    mAbis = abis;
  }

  public static class Dso {
    public final String name;
    public final String hash;

    public Dso (String name, String hash) {
      this.name = name;
      this.hash = hash;
    }
  }

  public static final class DsoManifest {

    public final Dso[] dsos;
    public DsoManifest(Dso[] dsos) {
      this.dsos = dsos;
    }

    /**
     * @return Dso manifest, or {@code null} if manifest is corrupt or illegible.
     */
    static final DsoManifest read(DataInput xdi) throws IOException {
      int version = xdi.readByte();
      if (version != MANIFEST_VERSION) {
        throw new RuntimeException("wrong dso manifest version");
      }

      int nrDso = xdi.readInt();
      if (nrDso < 0) {
        throw new RuntimeException("illegal number of shared libraries");
      }

      Dso[] dsos = new Dso[nrDso];
      for (int i = 0; i < nrDso; ++i) {
        dsos[i] = new Dso(xdi.readUTF(), xdi.readUTF());
      }
      return new DsoManifest(dsos);
    }

    public final void write(DataOutput xdo) throws IOException {
      xdo.writeByte(MANIFEST_VERSION);
      xdo.writeInt(dsos.length);
      for (int i = 0; i < dsos.length; ++i) {
        xdo.writeUTF(dsos[i].name);
        xdo.writeUTF(dsos[i].hash);
      }
    }
  }

  protected static final class InputDso implements Closeable {
    public final Dso dso;
    public final InputStream content;
    public InputDso(Dso dso, InputStream content) {
      this.dso = dso;
      this.content = content;
    }

    @Override
    public void close() throws IOException {
      content.close();
    }
  }

  protected abstract static class InputDsoIterator implements Closeable {

    abstract public boolean hasNext();
    abstract public InputDso next() throws IOException;

    @Override
    public void close() throws IOException {
      /* By default, do nothing */
    }
  }

  protected abstract static class Unpacker implements Closeable {
    protected abstract DsoManifest getDsoManifest() throws IOException;
    protected abstract InputDsoIterator openDsoIterator() throws IOException;
    @Override
    public void close() throws IOException {
      /* By default, do nothing */
    }
  }

  private static void writeState(File stateFileName, byte state) throws IOException {
    try (RandomAccessFile stateFile = new RandomAccessFile(stateFileName, "rw")) {
      stateFile.seek(0);
      stateFile.write(state);
      stateFile.setLength(stateFile.getFilePointer());
      stateFile.getFD().sync();
    }
  }

  /**
   * Delete files not mentioned in the given DSO list.
   */
  private void deleteUnmentionedFiles(Dso[] dsos) throws IOException {
    String[] existingFiles = soDirectory.list();
    if (existingFiles == null) {
      throw new IOException("unable to list directory " + soDirectory);
    }

    for (int i = 0; i < existingFiles.length; ++i) {
      String fileName = existingFiles[i];
      if (fileName.equals(STATE_FILE_NAME) ||
          fileName.equals(LOCK_FILE_NAME) ||
          fileName.equals(DEPS_FILE_NAME) ||
          fileName.equals(MANIFEST_FILE_NAME)) {
        continue;
      }

      boolean found = false;
      for (int j = 0; !found && j < dsos.length; ++j) {
        if (dsos[j].name.equals(fileName)) {
          found = true;
        }
      }

      if (!found) {
        File fileNameToDelete = new File(soDirectory, fileName);
        Log.v(TAG, "deleting unaccounted-for file " + fileNameToDelete);
        SysUtil.dumbDeleteRecursive(fileNameToDelete);
      }
    }
  }

  private void extractDso(InputDso iDso, byte[] ioBuffer) throws IOException {
    Log.i(TAG, "extracting DSO " + iDso.dso.name);
    if (!soDirectory.setWritable(true /* can write */, true /* owner only */)) {
      throw new IOException("cannot make directory writable for us: " + soDirectory);
    }
    File dsoFileName = new File(soDirectory, iDso.dso.name);
    RandomAccessFile dsoFile = null;
    try {
      dsoFile = new RandomAccessFile(dsoFileName, "rw");
    } catch (IOException ex) {
      Log.w(TAG, "error overwriting " + dsoFileName + " trying to delete and start over", ex);
      SysUtil.dumbDeleteRecursive(dsoFileName); // Throws on error; not existing is okay
      dsoFile = new RandomAccessFile(dsoFileName, "rw");
    }

    try {
      InputStream dsoContent = iDso.content;
      int sizeHint = dsoContent.available();
      if (sizeHint > 1) {
        SysUtil.fallocateIfSupported(dsoFile.getFD(), sizeHint);
      }
      SysUtil.copyBytes(dsoFile, iDso.content, Integer.MAX_VALUE, ioBuffer);
      dsoFile.setLength(dsoFile.getFilePointer()); // In case we shortened file
      if (!dsoFileName.setExecutable(true /* allow exec... */, false /* ...for everyone */)) {
        throw new IOException("cannot make file executable: " + dsoFileName);
      }
    } finally {
      dsoFile.close();
    }
  }

  private void regenerate(
      byte state,
      DsoManifest desiredManifest,
      InputDsoIterator dsoIterator) throws IOException {
    Log.v(TAG, "regenerating DSO store " + getClass().getName());
    File manifestFileName = new File(soDirectory, MANIFEST_FILE_NAME);
    try (RandomAccessFile manifestFile = new RandomAccessFile(manifestFileName, "rw")) {
      DsoManifest existingManifest = null;
      if (state == STATE_CLEAN) {
        try {
          existingManifest = DsoManifest.read(manifestFile);
        } catch (Exception ex) {
        Log.i(TAG, "error reading existing DSO manifest", ex);
        }
      }

      if (existingManifest == null) {
        existingManifest = new DsoManifest(new Dso[0]);
      }

      deleteUnmentionedFiles(desiredManifest.dsos);
      byte[] ioBuffer = new byte[32*1024];
      while (dsoIterator.hasNext()) {
        try (InputDso iDso = dsoIterator.next()) {
          boolean obsolete = true;
          for (int i = 0; obsolete && i < existingManifest.dsos.length; ++i) {
            if (existingManifest.dsos[i].name.equals(iDso.dso.name) &&
                existingManifest.dsos[i].hash.equals(iDso.dso.hash)) {
              obsolete = false;
            }
          }
          if (obsolete) {
            extractDso(iDso, ioBuffer);
          }
        }
      }
    }
  }

  private boolean refreshLocked(
      final FileLocker lock,
      final int flags,
      final byte[] deps) throws IOException {
    final File stateFileName = new File(soDirectory, STATE_FILE_NAME);
    byte state;
    try (RandomAccessFile stateFile = new RandomAccessFile(stateFileName, "rw")) {
      try {
        state = stateFile.readByte();
        if (state != STATE_CLEAN) {
          Log.v(TAG, "dso store " + soDirectory + " regeneration interrupted: wiping clean");
          state = STATE_DIRTY;
        }
      } catch (EOFException ex) {
        state = STATE_DIRTY;
      }
    }

    final File depsFileName = new File(soDirectory, DEPS_FILE_NAME);
    DsoManifest desiredManifest = null;
    try (RandomAccessFile depsFile = new RandomAccessFile(depsFileName, "rw")) {
      byte[] existingDeps = new byte[(int) depsFile.length()];
      if (depsFile.read(existingDeps) != existingDeps.length) {
        Log.v(TAG, "short read of so store deps file: marking unclean");
        state = STATE_DIRTY;
      }

      if (!Arrays.equals(existingDeps, deps)) {
        Log.v(TAG, "deps mismatch on deps store: regenerating");
        state = STATE_DIRTY;
      }

      if (state == STATE_DIRTY) {
        Log.v(TAG, "so store dirty: regenerating");
        writeState(stateFileName, STATE_DIRTY);

        try (Unpacker u = makeUnpacker()) {
          desiredManifest = u.getDsoManifest();
          try (InputDsoIterator idi = u.openDsoIterator()) {
            regenerate(state, desiredManifest, idi);
          }
        }
      }
    }

    if (desiredManifest == null) {
      return false; // No sync needed
    }

    final DsoManifest manifest = desiredManifest;

    Runnable syncer = new Runnable() {
        @Override
        public void run() {
          try {
            try {
              Log.v(TAG, "starting syncer worker");

              // N.B. We can afford to write the deps file and the manifest file without
              // synchronization or fsyncs because we've marked the DSO store STATE_DIRTY, which
              // will cause us to ignore all intermediate state when regenerating it.  That is,
              // it's okay for the depsFile or manifestFile blocks to hit the disk before the
              // actual DSO data file blocks as long as both hit the disk before we reset
              // STATE_CLEAN.

              try (RandomAccessFile depsFile = new RandomAccessFile(depsFileName, "rw")) {
                depsFile.write(deps);
                depsFile.setLength(depsFile.getFilePointer());
              }

              File manifestFileName = new File(soDirectory, MANIFEST_FILE_NAME);
              try (RandomAccessFile manifestFile = new RandomAccessFile(manifestFileName, "rw")) {
                manifest.write(manifestFile);
              }

              SysUtil.fsyncRecursive(soDirectory);
              writeState(stateFileName, STATE_CLEAN);
            } finally {
              Log.v(TAG, "releasing dso store lock for " + soDirectory + " (from syncer thread)");
              lock.close();
            }
          } catch (IOException ex) {
            throw new RuntimeException(ex);
          }
        }
      };

    if ((flags & PREPARE_FLAG_ALLOW_ASYNC_INIT) != 0) {
      new Thread(syncer, "SoSync:" + soDirectory.getName()).start();
    } else {
      syncer.run();
    }

    return true;
  }

  /**
   * Return an opaque blob of bytes that represents all the dependencies of this SoSource; if this
   * block differs from one we've previously saved, we go through the heavyweight refresh process
   * that involves calling {@link #getDsoManifest} and {@link #openDsoIterator}.
   *
   * Subclasses should override this method if {@link #getDsoManifest} is expensive.
   *
   * @return dependency block
   */
  protected byte[] getDepsBlock() throws IOException {
    // Parcel is fine: we never parse the parceled bytes, so it's okay if the byte representation
    // changes beneath us.
    Parcel parcel = Parcel.obtain();
    try (Unpacker u = makeUnpacker()) {
      Dso[] dsos = u.getDsoManifest().dsos;
      parcel.writeByte(MANIFEST_VERSION);
      parcel.writeInt(dsos.length);
      for (int i = 0; i < dsos.length; ++i) {
        parcel.writeString(dsos[i].name);
        parcel.writeString(dsos[i].hash);
      }
    }
    byte[] depsBlock = parcel.marshall();
    parcel.recycle();
    return depsBlock;
  }

  /**
   * Verify or refresh the state of the shared library store.
   */
  @Override
  protected void prepare(int flags) throws IOException {
    SysUtil.mkdirOrThrow(soDirectory);
    File lockFileName = new File(soDirectory, LOCK_FILE_NAME);
    FileLocker lock = FileLocker.lock(lockFileName);
    try {
      Log.v(TAG, "locked dso store " + soDirectory);
      if (refreshLocked(lock, flags, getDepsBlock())) {
        lock = null; // Lock transferred to syncer thread
      } else {
        Log.i(TAG, "dso store is up-to-date: " + soDirectory);
      }
    } finally {
      if (lock != null) {
        Log.v(TAG, "releasing dso store lock for " + soDirectory);
        lock.close();
      } else {
        Log.v(TAG, "not releasing dso store lock for "
            + soDirectory + " (syncer thread started)");
      }
    }
  }
}
