// Copyright 2004-present Facebook. All Rights Reserved.

package com.facebook.soloader;

import java.io.File;
import java.io.IOException;
import android.content.Context;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.zip.ZipFile;
import java.util.zip.ZipEntry;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.io.InputStream;
import java.io.FileOutputStream;
import java.util.HashMap;
import java.util.Enumeration;
import java.util.Arrays;

import android.util.Log;

/**
 * {@link SoSource} that extracts libraries from a zip file to the filesystem.
 */
public class ExtractFromZipSoSource extends UnpackingSoSource {

  protected final File mZipFileName;
  protected final String mZipSearchPattern;

  /**
   * @param context Application contextg
   * @param name Name of the DSO store
   * @param zipFileName Name of the zip file from which we extract; opened only on demand
   * @param zipSearchPattern Regular expression string matching DSOs in the zip file;
   *   subgroup 1 must be an ABI (as from Build.CPU_ABI) and subgroup 2 must be the
   *   shared library basename.
   */
  public ExtractFromZipSoSource(
      Context context,
      String name,
      File zipFileName,
      String zipSearchPattern) {
    super(context, name);
    mZipFileName = zipFileName;
    mZipSearchPattern = zipSearchPattern;
  }

  @Override
  protected Unpacker makeUnpacker() throws IOException {
    return new ZipUnpacker(this);
  }

  protected class ZipUnpacker extends Unpacker {

    private ZipDso[] mDsos;
    private final ZipFile mZipFile;
    private final UnpackingSoSource mSoSource;

    ZipUnpacker(final UnpackingSoSource soSource) throws IOException {
      mZipFile = new ZipFile(mZipFileName);
      mSoSource = soSource;
    }

    final ZipDso[] ensureDsos() {
      if (mDsos == null) {
        Set<String> librariesAbiSet = new LinkedHashSet<>();
        HashMap<String, ZipDso> providedLibraries = new HashMap<>();
        Pattern zipSearchPattern = Pattern.compile(mZipSearchPattern);
        String[] supportedAbis = SysUtil.getSupportedAbis();
        Enumeration<? extends ZipEntry> entries = mZipFile.entries();
        while (entries.hasMoreElements()) {
          ZipEntry entry = entries.nextElement();
          Matcher m = zipSearchPattern.matcher(entry.getName());
          if (m.matches()) {
            String libraryAbi = m.group(1);
            String soName = m.group(2);
            int abiScore = SysUtil.findAbiScore(supportedAbis, libraryAbi);
            if (abiScore >= 0) {
              librariesAbiSet.add(libraryAbi);
              ZipDso so = providedLibraries.get(soName);
              if (so == null || abiScore < so.abiScore) {
                providedLibraries.put(soName, new ZipDso(soName, entry, abiScore));
              }
            }
          }
        }

        mSoSource.setSoSourceAbis(librariesAbiSet.toArray(new String[librariesAbiSet.size()]));

        ZipDso[] dsos = providedLibraries.values().toArray(new ZipDso[providedLibraries.size()]);
        Arrays.sort(dsos);
        int nrFilteredDsos = 0;
        for (int i = 0; i < dsos.length; ++i) {
          ZipDso zd = dsos[i];
          if (shouldExtract(zd.backingEntry, zd.name)) {
            nrFilteredDsos += 1;
          } else {
            dsos[i] = null;
          }
        }
        ZipDso[] filteredDsos = new ZipDso[nrFilteredDsos];
        for (int i = 0, j = 0; i < dsos.length; ++i) {
          ZipDso zd = dsos[i];
          if (zd != null) {
            filteredDsos[j++] = zd;
          }
        }
        mDsos = filteredDsos;
      }
      return mDsos;
    }

    /**
     * Hook for subclasses to filter out certain library names from being extracted from the
     * zip file.
     *
     * @param soName Candidate soName
     * @param ze Zip entry for file to extract
     */
    protected boolean shouldExtract(ZipEntry ze, String soName) {
      return true;
    }

    @Override
    public void close() throws IOException {
      mZipFile.close();
    }

    @Override
    protected final DsoManifest getDsoManifest() throws IOException {
      return new DsoManifest(ensureDsos());
    }

    @Override
    protected final InputDsoIterator openDsoIterator() throws IOException {
      return new ZipBackedInputDsoIterator();
    }

    private final class ZipBackedInputDsoIterator extends InputDsoIterator {

      private int mCurrentDso;

      @Override
      public boolean hasNext() {
        ensureDsos();
        return mCurrentDso < mDsos.length;
      }

      @Override
      public InputDso next() throws IOException {
        ensureDsos();
        ZipDso zipDso = mDsos[mCurrentDso++];
        InputStream is = mZipFile.getInputStream(zipDso.backingEntry);
        try {
          InputDso ret = new InputDso(zipDso, is);
          is = null; // Transfer ownership
          return ret;
        } finally {
          if (is != null) {
            is.close();
          }
        }
      }
    }
  }

  private static final class ZipDso extends Dso implements Comparable {

    final ZipEntry backingEntry;
    final int abiScore;

    ZipDso(String name, ZipEntry backingEntry, int abiScore) {
      super(name, makePseudoHash(backingEntry));
      this.backingEntry = backingEntry;
      this.abiScore = abiScore;
    }

    private static String makePseudoHash(ZipEntry ze) {
      return String.format( // Yuck, but no real metadata
          "pseudo-zip-hash-1-%s-%s-%s-%s",
          ze.getName(),
          ze.getSize(),
          ze.getCompressedSize(),
          ze.getCrc());
    }

    @Override
    public int compareTo(Object other) {
      return name.compareTo(((ZipDso)other).name);
    }
  }
}
