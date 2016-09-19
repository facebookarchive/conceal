LOCAL_PATH := $(call my-dir)

local_c_includes := $(LOCAL_PATH)/include

include $(CLEAR_VARS)
LOCAL_MODULE := crypto
LOCAL_SRC_FILES := $(TARGET_ARCH_ABI)/libcrypto.a
LOCAL_CFLAGS    := -fdata-sections -ffunction-sections
LOCAL_EXPORT_C_INCLUDES := $(local_c_includes)
include $(PREBUILT_STATIC_LIBRARY)
