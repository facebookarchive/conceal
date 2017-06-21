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

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.jar.JarFile;
import java.util.jar.JarEntry;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

import android.os.Build;
import android.system.Os;
import android.system.ErrnoException;

import java.util.ArrayList;
import java.util.Map;
import java.util.Enumeration;

import java.io.FileInputStream;
import java.io.BufferedReader;
import java.io.FileReader;

import android.util.Log;

import com.facebook.soloader.UnpackingSoSource.DsoManifest;
import com.facebook.soloader.UnpackingSoSource.Dso;
import com.facebook.soloader.UnpackingSoSource.InputDso;
import com.facebook.soloader.UnpackingSoSource.InputDsoIterator;

/**
 * {@link SoSource} that retrieves libraries from an exopackage repository.
 */
public final class ExoSoSource extends UnpackingSoSource {

  public ExoSoSource(Context context, String name) {
    super(context, name);
  }

  @Override
  protected Unpacker makeUnpacker() throws IOException {
    return new ExoUnpacker(this);
  }

  private final class ExoUnpacker extends Unpacker {

    private final FileDso[] mDsos;

    ExoUnpacker(final UnpackingSoSource soSource) throws IOException {
      Context context = mContext;
      File exoDir = new File(
          "/data/local/tmp/exopackage/"
          + context.getPackageName()
          + "/native-libs/");

      ArrayList<FileDso> providedLibraries = new ArrayList<>();

      Set<String> librariesAbiSet = new LinkedHashSet<>();

      for (String abi : SysUtil.getSupportedAbis()) {
        File abiDir = new File(exoDir, abi);
        if (!abiDir.isDirectory()) {
          continue;
        }

        librariesAbiSet.add(abi);

        File metadataFileName = new File(abiDir, "metadata.txt");
        if (!metadataFileName.isFile()) {
          continue;
        }

        try (FileReader fr = new FileReader(metadataFileName);
            BufferedReader br = new BufferedReader(fr)) {
          String line;
          while ((line = br.readLine()) != null) {
            if (line.length() == 0) {
              continue;
            }

            int sep = line.indexOf(' ');
            if (sep == -1) {
              throw new RuntimeException("illegal line in exopackage metadata: [" + line + "]");
            }

            String soName = line.substring(0, sep) + ".so";
            int nrAlreadyProvided = providedLibraries.size();
            boolean found = false;
            for (int i = 0; i < nrAlreadyProvided; ++i) {
              if (providedLibraries.get(i).name.equals(soName)) {
                found = true;
                break;
              }
            }

            if (found) {
              continue;
            }

            String backingFileBaseName = line.substring(sep + 1);
            providedLibraries.add(
                new FileDso(
                    soName,
                    backingFileBaseName,
                    new File(abiDir, backingFileBaseName)));
          }
        }
      }

      soSource.setSoSourceAbis(librariesAbiSet.toArray(new String[librariesAbiSet.size()]));
      mDsos = providedLibraries.toArray(new FileDso[providedLibraries.size()]);
    }

    @Override
    protected DsoManifest getDsoManifest() throws IOException {
      return new DsoManifest(mDsos);
    }

    @Override
    protected InputDsoIterator openDsoIterator() throws IOException {
      return new FileBackedInputDsoIterator();
    }

    private final class FileBackedInputDsoIterator extends InputDsoIterator {
      private int mCurrentDso;

      @Override
      public boolean hasNext() {
        return mCurrentDso < mDsos.length;
      }

      @Override
      public InputDso next() throws IOException {
        FileDso fileDso = mDsos[mCurrentDso++];
        FileInputStream dsoFile = new FileInputStream(fileDso.backingFile);
        try {
          InputDso ret = new InputDso(fileDso, dsoFile);
          dsoFile = null; // Ownership transferred
          return ret;
        } finally {
          if (dsoFile != null) {
            dsoFile.close();
          }
        }
      }
    }
  }

  private static final class FileDso extends Dso {
    final File backingFile;
    FileDso(String name, String hash, File backingFile) {
      super(name, hash);
      this.backingFile = backingFile;
    }
  }
}
