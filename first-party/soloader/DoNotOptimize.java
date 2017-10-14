// Copyright 2004-present Facebook. All Rights Reserved.

package com.facebook.soloader;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.RetentionPolicy.CLASS;

/**
 * A hint (which may or may not be observed) to any optimizers in our tool
 * chain that we don't want optimizations being applied to the annotated
 * elements.
 */
@Target({ ElementType.TYPE, ElementType.FIELD, ElementType.METHOD, ElementType.CONSTRUCTOR })
@Retention(CLASS)
public @interface DoNotOptimize {
}
