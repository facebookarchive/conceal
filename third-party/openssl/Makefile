LATEST_OPENSSL := OpenSSL_1_0_2g

SRC_OPENSSL := openssl-1.0.2
OUT_OPENSSL := .
TMP_TOOLCHAIN := /tmp/toolchain
CONFIG_OPTIONS := -fPIC -ffunction-sections -fdata-sections
ORIGINAL_PATH := $$PATH
#
# Requires ANDROID_NDK to be set
# Example:
# export ANDROID_NDK=/opt/android-ndk-r11c
#
BASE_TOOLCHAIN := $$ANDROID_NDK/build/tools/make-standalone-toolchain.sh --arch=

ARCHS := arm64-v8a armeabi armeabi-v7a x86 x86_64

#
# Generates libcrypto.a for given ARCH
#
define gen_arch_libcrypto
        echo $(TMP_TOOLCHAIN)
	-rm -rf $(TMP_TOOLCHAIN)/$1
	$(BASE_TOOLCHAIN)$2 --install-dir=$(TMP_TOOLCHAIN)/$1
	export PATH=$(TMP_TOOLCHAIN)/$1/bin:$(ORIGINAL_PATH) && \
		cd $(SRC_OPENSSL) && \
                mkdir -p ../$(OUT_OPENSSL)/$1 && \
		./Configure$5 $(CONFIG_OPTIONS) --cross-compile-prefix=$(TMP_TOOLCHAIN)/$1/bin/$3- $4 && make depend && make -j20 && \
		cp libcrypto.a ../$(OUT_OPENSSL)/$1/libcrypto.a
	-$(MAKE) -C $(SRC_OPENSSL) clean
endef

.PHONY: all
all: check clone $(ARCHS)

# ifndef/endif should not be indented, is processed before Makefile is run
.PHONE: check
check:
ifndef ANDROID_NDK
	$(error ANDROID_NDK is not set)
endif

.PHONY: clone
clone:
	-git clone -b $(LATEST_OPENSSL) --single-branch git://git.openssl.org/openssl.git $(SRC_OPENSSL)

.PHONY: arm64-v8a
arm64-v8a:
	$(call gen_arch_libcrypto,$@,arm64,aarch64-linux-android,android, no-asm)

.PHONY: armeabi
armeabi:
	$(call gen_arch_libcrypto,$@,arm,arm-linux-androideabi,android)

.PHONY: armeabi-v7a
armeabi-v7a:
	$(call gen_arch_libcrypto,$@,arm,arm-linux-androideabi,android-armv7)

.PHONY: x86
x86:
	$(call gen_arch_libcrypto,$@,$@,i686-linux-android,android-x86)

.PHONY: x86_64
x86_64:
	$(call gen_arch_libcrypto,$@,$@,x86_64-linux-android,linux-x86_64, no-asm)

.PHONY: clean
clean:
	-rm -rf $(SRC_OPENSSL)
	-rm -rf $(TMP_TOOLCHAIN)
