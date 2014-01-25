LOCAL_PATH := $(call my-dir)

ifeq ($(strip $(TARGET_IS_64_BIT)),true)
  include $(LOCAL_PATH)/build-config-64.mk
else
  include $(LOCAL_PATH)/build-config-32.mk
endif
include $(LOCAL_PATH)/Crypto.mk
