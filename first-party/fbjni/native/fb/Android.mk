LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
       $(LOCAL_PATH)/assert.cpp \
       $(LOCAL_PATH)/jni/ByteBuffer.cpp \
       $(LOCAL_PATH)/jni/Countable.cpp \
       $(LOCAL_PATH)/jni/Environment.cpp \
       $(LOCAL_PATH)/jni/Exceptions.cpp \
       $(LOCAL_PATH)/jni/fbjni.cpp \
       $(LOCAL_PATH)/jni/Hybrid.cpp \
       $(LOCAL_PATH)/jni/jni_helpers.cpp \
       $(LOCAL_PATH)/jni/LocalString.cpp \
       $(LOCAL_PATH)/jni/OnLoad.cpp \
       $(LOCAL_PATH)/jni/References.cpp \
       $(LOCAL_PATH)/jni/WeakReference.cpp \
       $(LOCAL_PATH)/log.cpp \
       $(LOCAL_PATH)/lyra/lyra.cpp \
       $(LOCAL_PATH)/onload.cpp \

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include

LOCAL_CFLAGS := -DLOG_TAG=\"libfb\" -DDISABLE_CPUCAP -DDISABLE_XPLAT -fexceptions -frtti
LOCAL_CFLAGS += -Wall -Werror
# encapsulate each symbol so it can be removed later
LOCAL_CFLAGS += -fdata-sections -ffunction-sections
# include/utils/threads.h has unused parameters
LOCAL_CFLAGS += -Wno-unused-parameter
ifeq ($(TOOLCHAIN_PERMISSIVE),true)
  LOCAL_CFLAGS += -Wno-error=unused-but-set-variable
endif
LOCAL_CFLAGS += -DHAVE_POSIX_CLOCKS

CXX11_FLAGS := -std=gnu++11
LOCAL_CFLAGS += $(CXX11_FLAGS)

LOCAL_EXPORT_CPPFLAGS := $(CXX11_FLAGS)

LOCAL_LDLIBS := -llog -ldl -landroid
LOCAL_LDFLAGS   += -Wl,--gc-sections -Wl,--exclude-libs,ALL
LOCAL_EXPORT_LDLIBS := -llog

LOCAL_MODULE := libfb

include $(BUILD_SHARED_LIBRARY)
