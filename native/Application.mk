# Copyright 2004-present Facebook. All Rights Reserved.

APP_ABI := armeabi armeabi-v7a arm64-v8a x86 x86_64
NDK_TOOLCHAIN_VERSION := 4.9
#APP_STL := stlport_shared

#APP_STL := gnustl_shared
APP_STL := gnustl_static

# Enable c++11 extentions in source code
APP_CPPFLAGS += -std=c++14
