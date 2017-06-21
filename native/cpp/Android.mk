LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := concealcpp
LOCAL_CFLAGS    := -fvisibility=hidden -Os -fdata-sections -ffunction-sections -fexceptions -std=gnu++1y
LOCAL_SRC_FILES := Cipher.cpp CryptoConfig.cpp Decrypt.cpp DecryptStream.cpp Encrypt.cpp EncryptStream.cpp MacConfig.cpp MacDecoder.cpp MacEncoder.cpp PBKDF2.cpp SliceMethods.cpp TailBuffer.cpp TransformBuffer.cpp WithState.cpp
# LOCAL_LDLIBS    := -llog
# LOCAL_LDFLAGS   += -Wl,--gc-sections -Wl,--exclude-libs,ALL
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include

LOCAL_STATIC_LIBRARIES += crypto
include $(BUILD_STATIC_LIBRARY)

$(call import-module,openssl)
