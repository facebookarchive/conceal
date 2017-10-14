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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.StrictMode;
import android.text.TextUtils;
import android.util.Log;

import dalvik.system.BaseDexClassLoader;

/**
 * Native code loader.
 *
 * <p> To load a native library, call the static method {@link #loadLibrary} from the
 * static  initializer of the Java class declaring the native methods. The argument
 * should be the library's short name.
 *
 * <p>For example, if the native code is in libmy_jni_methods.so:
 * <pre>
 * {@code
 * class MyClass {
 *   static {
 *     SoLoader.loadLibrary("my_jni_methods");
 *   }
 * }
 * }
 * </pre>
 *
 * <p> Before any library can be loaded SoLoader needs to be initialized. The application using
 * SoLoader should do that by calling SoLoader.init early on app initialization path. The call must
 * happen before any class using SoLoader in its static initializer is loaded.
 */
public class SoLoader {

  /* package */ static final String TAG = "SoLoader";
  /* package */ static final boolean DEBUG = false;
  /* package */ static final boolean SYSTRACE_LIBRARY_LOADING;
  /* package */ static SoFileLoader sSoFileLoader;

  /**
   * Ordered list of sources to consult when trying to load a shared library or one of its
   * dependencies. {@code null} indicates that SoLoader is uninitialized.
   */
  @Nullable private static SoSource[] sSoSources = null;

  /**
   * Records the sonames (e.g., "libdistract.so") of shared libraries we've loaded.
   */
  private static final Set<String> sLoadedLibraries = new HashSet<>();

  /**
   * Holds previous thread strict mode policy during recursive calls to loadLibraryBySoName.
   */
  @Nullable private static StrictMode.ThreadPolicy sOldPolicy = null;

  /**
   * Wrapper for System.loadLlibrary.
   */
  @Nullable private static SystemLoadLibraryWrapper sSystemLoadLibraryWrapper = null;

  /**
   * Name of the directory we use for extracted DSOs from built-in SO sources (APK, exopackage)
   */
  private static String SO_STORE_NAME_MAIN = "lib-main";

  /**
   * Enable the exopackage SoSource.
   */
  public static final int SOLOADER_ENABLE_EXOPACKAGE = (1<<0);

  /**
   * Allow deferring some initialization work to asynchronous background threads.  Shared libraries
   * are nevertheless ready to load as soon as init returns.
   */
  public static final int SOLOADER_ALLOW_ASYNC_INIT = (1<<1);

  public static final int SOLOADER_LOOK_IN_ZIP = (1<<2);

  private static int sFlags;

  static {
    boolean shouldSystrace = false;
    try {
      shouldSystrace = Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2;
    } catch (NoClassDefFoundError | UnsatisfiedLinkError e) {
      // In some test contexts, the Build class and/or some of its dependencies do not exist.
    }

    SYSTRACE_LIBRARY_LOADING = shouldSystrace;
  }

  public static void init(Context context, int flags) throws IOException {
    init(context, flags, null);
  }

  /**
   * Initializes native code loading for this app; this class's other static facilities cannot be
   * used until this {@link #init} is called. This method is idempotent: calls after the first are
   * ignored.
   *
   * @param context application context.
   * @param flags Zero or more of the SOLOADER_* flags
   * @param soFileLoader
   */
  public static void init(Context context, int flags, @Nullable SoFileLoader soFileLoader)
      throws IOException {
    StrictMode.ThreadPolicy oldPolicy = StrictMode.allowThreadDiskWrites();
    try {
      initImpl(context, flags, soFileLoader);
    } finally {
      StrictMode.setThreadPolicy(oldPolicy);
    }
  }

  /**
   * Backward compatibility
   */
  public static void init(Context context, boolean nativeExopackage) {
    try {
      init(context, nativeExopackage ? SOLOADER_ENABLE_EXOPACKAGE : 0);
    } catch (IOException ex) {
      throw new RuntimeException(ex);
    }
  }

  private static synchronized void initImpl(
      Context context,
      int flags,
      @Nullable SoFileLoader soFileLoader)
      throws IOException {
    if (sSoSources == null) {
      sFlags = flags;

      initSoLoader(soFileLoader);

      ArrayList<SoSource> soSources = new ArrayList<>();

      //
      // Add SoSource objects for each of the system library directories.
      //

      String LD_LIBRARY_PATH = System.getenv("LD_LIBRARY_PATH");
      if (LD_LIBRARY_PATH == null) {
        LD_LIBRARY_PATH = "/vendor/lib:/system/lib";
      }

      String[] systemLibraryDirectories = LD_LIBRARY_PATH.split(":");
      for (int i = 0; i < systemLibraryDirectories.length; ++i) {
        // Don't pass DirectorySoSource.RESOLVE_DEPENDENCIES for directories we find on
        // LD_LIBRARY_PATH: Bionic's dynamic linker is capable of correctly resolving dependencies
        // these libraries have on each other, so doing that ourselves would be a waste.
        File systemSoDirectory = new File(systemLibraryDirectories[i]);
        soSources.add(
            new DirectorySoSource(
                systemSoDirectory,
                DirectorySoSource.ON_LD_LIBRARY_PATH));
      }

      //
      // We can only proceed forward if we have a Context. The prominent case
      // where we don't have a Context is barebones dalvikvm instantiations. In
      // that case, the caller is responsible for providing a correct LD_LIBRARY_PATH.
      //

      if (context != null) {
        //
        // Prepend our own SoSource for our own DSOs.
        //

        if ((flags & SOLOADER_ENABLE_EXOPACKAGE) != 0) {
          soSources.add(0, new ExoSoSource(context, SO_STORE_NAME_MAIN));
        } else {
          ApplicationInfo applicationInfo = context.getApplicationInfo();
          boolean isSystemApplication =
              (applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0 &&
              (applicationInfo.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0;
          int apkSoSourceFlags;
          if (isSystemApplication) {
            apkSoSourceFlags = 0;
          } else {
            apkSoSourceFlags = ApkSoSource.PREFER_ANDROID_LIBS_DIRECTORY;
            int ourSoSourceFlags = 0;

            // On old versions of Android, Bionic doesn't add our library directory to its internal
            // search path, and the system doesn't resolve dependencies between modules we ship. On
            // these systems, we resolve dependencies ourselves. On other systems, Bionic's built-in
            // resolver suffices.

            if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.JELLY_BEAN_MR1) {
              ourSoSourceFlags |= DirectorySoSource.RESOLVE_DEPENDENCIES;
            }

            SoSource ourSoSource = new DirectorySoSource(
                new File(applicationInfo.nativeLibraryDir),
                ourSoSourceFlags);
            soSources.add(0, ourSoSource);
          }

          soSources.add(0, new ApkSoSource(context, SO_STORE_NAME_MAIN, apkSoSourceFlags));
        }
      }

      SoSource[] finalSoSources = soSources.toArray(new SoSource[soSources.size()]);
      int prepareFlags = makePrepareFlags();
      for (int i = finalSoSources.length; i-- > 0;) {
        finalSoSources[i].prepare(prepareFlags);
      }
      sSoSources = finalSoSources;
    }
  }

  private static int makePrepareFlags() {
    int prepareFlags = 0;
    if ((sFlags & SOLOADER_ALLOW_ASYNC_INIT) != 0) {
      prepareFlags |= SoSource.PREPARE_FLAG_ALLOW_ASYNC_INIT;
    }
    return prepareFlags;
  }

  private static synchronized void initSoLoader(@Nullable SoFileLoader soFileLoader) {
    if (soFileLoader != null) {
      sSoFileLoader = soFileLoader;
      return;
    }

    final Runtime runtime = Runtime.getRuntime();
    final Method nativeLoadRuntimeMethod = getNativeLoadRuntimeMethod();

    final boolean hasNativeLoadMethod = nativeLoadRuntimeMethod != null;

    final String localLdLibraryPath =
        hasNativeLoadMethod ? Api14Utils.getClassLoaderLdLoadLibrary() : null;
    final String localLdLibraryPathNoZips = makeNonZipPath(localLdLibraryPath);

    sSoFileLoader = new SoFileLoader() {
      @Override
      public void load(final String pathToSoFile, final int loadFlags) {
        if (hasNativeLoadMethod) {
          final boolean inZip = (loadFlags & SOLOADER_LOOK_IN_ZIP) == SOLOADER_LOOK_IN_ZIP;
          final String path = inZip ? localLdLibraryPath : localLdLibraryPathNoZips;
          try {
            synchronized (runtime) {
              String error = (String)nativeLoadRuntimeMethod.invoke(
                  runtime,
                  pathToSoFile,
                  SoLoader.class.getClassLoader(),
                  path);
              if (error != null) {
                throw new UnsatisfiedLinkError(error);
              }
            }
          } catch (IllegalAccessException
              | IllegalArgumentException
              | InvocationTargetException e) {
            final String errMsg = "Error: Cannot load " + pathToSoFile;
            Log.e(TAG, errMsg);
            throw new RuntimeException(errMsg, e);
          }
        } else {
          System.load(pathToSoFile);
        }
      }
    };
  }

  @Nullable
  private static Method getNativeLoadRuntimeMethod() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
      return null;
    }

    try {
      final Method method =
          Runtime.class
              .getDeclaredMethod("nativeLoad", String.class, ClassLoader.class, String.class);
      method.setAccessible(true);
      return method;
    } catch (final NoSuchMethodException | SecurityException e) {
      Log.w(TAG, "Cannot get nativeLoad method", e);
      return null;
    }
  }

  /**
   * Turn shared-library loading into a no-op.  Useful in special circumstances.
   */
  public static void setInTestMode() {
    sSoSources = new SoSource[]{new NoopSoSource()};
  }

  /**
   * Make shared-library loading delegate to the system.  Useful for tests.
   */
  public static void deinitForTest() {
    sSoSources = null;
  }

  /**
   * Provide a wrapper object for calling {@link System#loadLibrary}.
   * This is useful for controlling which ClassLoader libraries are loaded into.
   */
  public static void setSystemLoadLibraryWrapper(SystemLoadLibraryWrapper wrapper) {
    sSystemLoadLibraryWrapper = wrapper;
  }

  public static final class WrongAbiError extends UnsatisfiedLinkError {
    WrongAbiError(Throwable cause) {
      super("APK was built for a different platform");
      initCause(cause);
    }
  }

  public static void loadLibrary(String shortName) {
    loadLibrary(shortName, 0);
  }

  /**
   * Load a shared library, initializing any JNI binding it contains.
   *
   * @param shortName Name of library to find, without "lib" prefix or ".so" suffix
   * @param loadFlags Control flags for the loading behavior. See available flags under
   *                  {@link SoSource} (LOAD_FLAG_XXX).
   */
  public static synchronized void loadLibrary(String shortName, int loadFlags)
      throws UnsatisfiedLinkError
  {
    if (sSoSources == null) {
      // This should never happen during normal operation,
      // but if we're running in a non-Android environment,
      // fall back to System.loadLibrary.
      if ("http://www.android.com/".equals(System.getProperty("java.vendor.url"))) {
        // This will throw.
        assertInitialized();
      } else {
        // Not on an Android system.  Ask the JVM to load for us.
        if (sSystemLoadLibraryWrapper != null) {
          sSystemLoadLibraryWrapper.loadLibrary(shortName);
        } else {
          System.loadLibrary(shortName);
        }
        return;
      }
    }

    String mergedLibName = MergedSoMapping.mapLibName(shortName);
    String nameToLoad = mergedLibName != null ? mergedLibName : shortName;

    try {
      loadLibraryBySoName(System.mapLibraryName(nameToLoad), loadFlags);
    } catch (IOException ex) {
      throw new RuntimeException(ex);
    } catch (UnsatisfiedLinkError ex) {
      String message = ex.getMessage();
      if (message != null && message.contains("unexpected e_machine:")) {
        throw new WrongAbiError(ex);
      }
      throw ex;
    }

    if (mergedLibName != null) {
      if (SYSTRACE_LIBRARY_LOADING) {
        Api18TraceUtils.beginTraceSection("MergedSoMapping.invokeJniOnload[" + shortName + "]");
      }
      try {
        // We trust the JNI merging code to prevent us from
        // invoking JNI_OnLoad more than once because
        // it's more memory-efficient than tracking this in Java.
        MergedSoMapping.invokeJniOnload(shortName);
      } finally {
        if (SYSTRACE_LIBRARY_LOADING) {
          Api18TraceUtils.endSection();
        }
      }
    }
  }

  /**
   * Unpack library and its dependencies, returning the location of the unpacked library file.  All
   * non-system dependencies of the given library will either be on LD_LIBRARY_PATH or will be in
   * the same directory as the returned File.
   *
   * @param shortName Name of library to find, without "lib" prefix or ".so" suffix
   * @return Unpacked DSO location
   */
  public static File unpackLibraryAndDependencies(String shortName)
      throws UnsatisfiedLinkError
  {
    assertInitialized();
    try {
      return unpackLibraryBySoName(System.mapLibraryName(shortName));
    } catch (IOException ex) {
      throw new RuntimeException(ex);
    }
  }

  public static synchronized void loadLibraryBySoName(String soName, int loadFlags)
      throws IOException {
    int result = sLoadedLibraries.contains(soName)
      ? SoSource.LOAD_RESULT_LOADED
      : SoSource.LOAD_RESULT_NOT_FOUND;

    if (result == SoSource.LOAD_RESULT_NOT_FOUND) {

      // This way, we set the thread policy only one per loadLibrary no matter how many dependencies
      // we load.  Each call to StrictMode.allowThreadDiskWrites allocates.
      boolean restoreOldPolicy = false;
      if (sOldPolicy == null) {
        sOldPolicy = StrictMode.allowThreadDiskReads();
        restoreOldPolicy = true;
      }

      if (SYSTRACE_LIBRARY_LOADING) {
        Api18TraceUtils.beginTraceSection("SoLoader.loadLibrary[" + soName + "]");
      }

      try {
        for (int i = 0; result == SoSource.LOAD_RESULT_NOT_FOUND && i < sSoSources.length; ++i) {
          result = sSoSources[i].loadLibrary(soName, loadFlags);
        }
      } finally {
        if (SYSTRACE_LIBRARY_LOADING) {
          Api18TraceUtils.endSection();
        }

        if (restoreOldPolicy) {
          StrictMode.setThreadPolicy(sOldPolicy);
          sOldPolicy = null;
        }
      }
    }

    if (result == SoSource.LOAD_RESULT_NOT_FOUND) {
      throw new UnsatisfiedLinkError("couldn't find DSO to load: " + soName);
    }

    if (result == SoSource.LOAD_RESULT_LOADED) {
      sLoadedLibraries.add(soName);
    }
  }

  @Nullable
  public static String makeNonZipPath(final String localLdLibraryPath) {
    if (localLdLibraryPath == null) {
      return null;
    }

    final String[] paths = localLdLibraryPath.split(":");
    final ArrayList<String> pathsWithoutZip = new ArrayList<String>(paths.length);
    for (final String path : paths) {
      if (path.contains("!")) {
        continue;
      }
      pathsWithoutZip.add(path);
    }

    return TextUtils.join(":", pathsWithoutZip);
  }


  public static Set<String> getLoadedLibrariesNames() {
    return sLoadedLibraries;
  }

  /* package */ static File unpackLibraryBySoName(String soName) throws IOException {
    for (int i = 0; i < sSoSources.length; ++i) {
      File unpacked = sSoSources[i].unpackLibrary(soName);
      if (unpacked != null) {
        return unpacked;
      }
    }

    throw new FileNotFoundException(soName);
  }

  private static void assertInitialized() {
    if (sSoSources == null) {
      throw new RuntimeException("SoLoader.init() not yet called");
    }
  }

  /**
   * Add a new source of native libraries.  SoLoader consults the new source before any
   * currently-installed source.
   *
   * @param extraSoSource The SoSource to install
   */
  public static synchronized void prependSoSource(SoSource extraSoSource) throws IOException {
    assertInitialized();
    extraSoSource.prepare(makePrepareFlags());
    SoSource[] newSoSources = new SoSource[sSoSources.length+1];
    newSoSources[0] = extraSoSource;
    System.arraycopy(sSoSources, 0, newSoSources, 1, sSoSources.length);
    sSoSources = newSoSources;
  }

  /**
   * Retrieve an LD_LIBRARY_PATH value suitable for using the native linker to resolve our
   * shared libraries.
   */
  public static synchronized String makeLdLibraryPath() {
    assertInitialized();
    ArrayList<String> pathElements = new ArrayList<>();
    SoSource[] soSources = sSoSources;
    for (int i = 0; i < soSources.length; ++i) {
      soSources[i].addToLdLibraryPath(pathElements);
    }
    return TextUtils.join(":", pathElements);
  }

  /**
   * This function ensure that every SoSources Abi is supported for at least one
   * abi in SysUtil.getSupportedAbis
   * @return true if all SoSources have their Abis supported
   */
  public static boolean areSoSourcesAbisSupported() {
    SoSource[] soSources = sSoSources;
    if (soSources == null) {
      return false;
    }

    String supportedAbis[] = SysUtil.getSupportedAbis();
    for (int i = 0; i < soSources.length; ++i) {
      String[] soSourceAbis = soSources[i].getSoSourceAbis();
      for (int j = 0; j < soSourceAbis.length; ++j) {
        boolean soSourceSupported = false;
        for (int k = 0; k < supportedAbis.length && !soSourceSupported; ++k) {
          soSourceSupported = soSourceAbis[j].equals(supportedAbis[k]);
        }
        if (!soSourceSupported) {
          return false;
        }
      }
    }

    return true;
  }

  @DoNotOptimize
  @TargetApi(14)
  private static class Api14Utils {
    public static String getClassLoaderLdLoadLibrary() {
      final ClassLoader classLoader = SoLoader.class.getClassLoader();

      if (!(classLoader instanceof BaseDexClassLoader)) {
        throw new IllegalStateException(
            "ClassLoader " + classLoader.getClass().getName() + " should be of type BaseDexClassLoader");
      }
      try {
        final BaseDexClassLoader baseDexClassLoader = (BaseDexClassLoader) classLoader;
        final Method getLdLibraryPathMethod = BaseDexClassLoader.class.getMethod("getLdLibraryPath");

        return (String) getLdLibraryPathMethod.invoke(baseDexClassLoader);
      } catch (Exception e) {
        throw new RuntimeException("Cannot call getLdLibraryPath", e);
      }
    }
  }
}
