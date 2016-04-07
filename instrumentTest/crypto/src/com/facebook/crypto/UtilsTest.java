/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto;

import android.annotation.TargetApi;
import android.os.Build;
import android.test.InstrumentationTestCase;

import junit.framework.Assert;

import static com.facebook.crypto.CryptoTestUtils.toBytes;

/**
 * Test auxiliary methods from CryptoTestUtils
 */
@TargetApi(Build.VERSION_CODES.GINGERBREAD)
public class UtilsTest extends InstrumentationTestCase {
    public void testToBytesMethod() throws Exception {
        byte[] value1 = toBytes("ab121b");
        byte[] value2 = toBytes("ab121bE");
        byte[] value3 = toBytes("ab1 21B");
        byte[] value4 = toBytes("AB1xxxxx21b");

        Assert.assertEquals((byte) 0xab, value1[0]);
        Assert.assertEquals((byte) 0x12, value1[1]);
        Assert.assertEquals((byte) 0x1b, value1[2]);

        Assert.assertEquals((byte) 0xab, value2[0]);
        Assert.assertEquals((byte) 0x12, value2[1]);
        Assert.assertEquals((byte) 0x1b, value2[2]);

        Assert.assertEquals((byte) 0xab, value3[0]);
        Assert.assertEquals((byte) 0x12, value3[1]);
        Assert.assertEquals((byte) 0x1b, value3[2]);

        Assert.assertEquals((byte) 0xab, value4[0]);
        Assert.assertEquals((byte) 0x12, value4[1]);
        Assert.assertEquals((byte) 0x1b, value4[2]);
    }
}