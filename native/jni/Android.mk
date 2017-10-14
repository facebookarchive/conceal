LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := concealjni
LOCAL_CFLAGS    := -fvisibility=hidden -Os -fdata-sections -ffunction-sections -fexceptions -std=gnu++1y
LOCAL_SRC_FILES := CipherHybrid.cpp DecryptHybrid.cpp EncryptHybrid.cpp JavaArrays.cpp JKeyChain.cpp KeyChainFromJava.cpp MacDecoderHybrid.cpp MacEncoderHybrid.cpp OnLoad.cpp PBKDF2Hybrid.cpp
LOCAL_LDLIBS    := -llog
LOCAL_LDFLAGS   += -Wl,--gc-sections -Wl,--exclude-libs,ALL

LOCAL_STATIC_LIBRARIES = concealcpp
LOCAL_STATIC_LIBRARIES += fb

include $(BUILD_SHARED_LIBRARY)

$(call import-module,cpp)
$(call import-module,fb)
