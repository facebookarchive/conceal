.NOTPARALLEL:

#
# For all the available TAGS see:
# http://git.openssl.org/?p=openssl.git;a=tags
#
LATEST_OPENSSL := OpenSSL_1_0_2g

SRC_OPENSSL := src_openssl
OUT_OPENSSL := openssl
TMP_TOOLCHAIN := /tmp/toolchain
CONFIG_OPTIONS := -fPIC -ffunction-sections -fdata-sections

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
	-rm -rf $(TMP_TOOLCHAIN)/$1
	$(BASE_TOOLCHAIN)$2 --install-dir=$(TMP_TOOLCHAIN)/$1
	cd $(SRC_OPENSSL) && \
                mkdir -p ../$(OUT_OPENSSL)/$1 && \
		./Configure$5 $(CONFIG_OPTIONS) --cross-compile-prefix=$(TMP_TOOLCHAIN)/$1/bin/$3- $4 && make depend && make -j20 && \
		cp libcrypto.a ../$(OUT_OPENSSL)/$1/libcrypto.a
	-$(MAKE) -C $(SRC_OPENSSL) clean
endef

.PHONY: all
all: clone $(ARCHS)

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
