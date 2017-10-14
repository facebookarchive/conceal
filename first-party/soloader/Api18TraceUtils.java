// Copyright 2004-present Facebook. All Rights Reserved.

package com.facebook.soloader;

import android.annotation.TargetApi;
import android.os.Trace;

/**
 * Encapsulate Trace calls introduced in API18 into an independent class
 * so that, we don't fail preverification down level on versions below API 18.
 */
@DoNotOptimize
@TargetApi(18)
class Api18TraceUtils {

  public static void beginTraceSection(String sectionName) {
    Trace.beginSection(sectionName);
  }

  public static void endSection() {
    Trace.endSection();
  }
}
