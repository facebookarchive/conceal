/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.proguard.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.RetentionPolicy.CLASS;

/**
 * Add this annotation to any method with a void return signature to allow proguard to strip
 * it out for non-internal builds.  Proguard can usually strip out the code referenced within this
 * method transitively allowing for a significant reduction in code volume for certain
 * specialized cases.
 */
@Target({ ElementType.METHOD })
@Retention(CLASS)
public @interface InternalBuildOnly {
}
