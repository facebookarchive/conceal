LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := conceal
LOCAL_CFLAGS    := -fvisibility=hidden -Os -fdata-sections -ffunction-sections
LOCAL_SRC_FILES := gcm.c gcm_util.c hmac.c hmac_util.c pbkdf2.c init.c util.c
LOCAL_LDLIBS    := -llog
LOCAL_LDFLAGS   += -Wl,--gc-sections -Wl,--exclude-libs,ALL

LOCAL_SHARED_LIBRARIES += crypto
include $(BUILD_SHARED_LIBRARY)

$(call import-module,openssl)
