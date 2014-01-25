# Auto-generated - DO NOT EDIT!
# To regenerate, edit openssl.config, then run:
#     ./import_openssl.sh import /path/to/openssl-1.0.1e.tar.gz
#
# Before including this file, the local Android.mk must define the following
# variables:
#
#    local_c_flags
#    local_c_includes
#    local_additional_dependencies
#
# This script will define the following variables:
#
#    target_c_flags
#    target_c_includes
#    target_src_files
#
#    host_c_flags
#    host_c_includes
#    host_src_files
#

# Ensure these are empty.
unknown_arch_c_flags :=
unknown_arch_src_files :=
unknown_arch_exclude_files :=


common_c_flags := \
  -DNO_WINDOWS_BRAINDEATH \

common_src_files := \
  crypto/aes/aes_core.c \
  crypto/aes/aes_cbc.c \
  crypto/aes/aes_ctr.c \
  crypto/aes/aes_misc.c \
  crypto/aes/aes_wrap.c \
  crypto/asn1/ameth_lib.c \
  crypto/bio/b_print.c \
  crypto/bio/bio_lib.c \
  crypto/buffer/buf_str.c \
  crypto/cryptlib.c \
  crypto/cversion.c \
  crypto/ebcdic.c \
  crypto/err/err.c \
  crypto/evp/digest.c \
  crypto/evp/e_aes.c \
  crypto/evp/evp_enc.c \
  crypto/evp/evp_lib.c \
  crypto/evp/m_sha1.c \
  crypto/evp/p_lib.c \
  crypto/evp/pmeth_lib.c \
  crypto/ex_data.c \
  crypto/hmac/hmac.c \
  crypto/lhash/lhash.c \
  crypto/mem.c \
  crypto/mem_clr.c \
  crypto/mem_dbg.c \
  crypto/modes/cbc128.c \
  crypto/modes/ctr128.c \
  crypto/modes/gcm128.c \
  crypto/o_dir.c \
  crypto/o_init.c \
  crypto/o_str.c \
  crypto/o_time.c \
  crypto/objects/obj_dat.c \
  crypto/rand/md_rand.c \
  crypto/rand/rand_egd.c \
  crypto/rand/rand_lib.c \
  crypto/rand/rand_unix.c \
  crypto/sha/sha1_one.c \
  crypto/sha/sha1dgst.c \
  crypto/sha/sha_dgst.c \
  crypto/stack/stack.c \
  crypto/uid.c \

local_c_includes += \
  $(LOCAL_PATH) \
  $(LOCAL_PATH)/crypto \
  $(LOCAL_PATH)/crypto/asn1 \
  $(LOCAL_PATH)/crypto/evp \
  $(LOCAL_PATH)/crypto/modes \
  $(LOCAL_PATH)/include \
  $(LOCAL_PATH)/include/openssl \

arm_c_flags := \
  -DAES_ASM \
  -DGHASH_ASM \
  -DOPENSSL_BN_ASM_GF2m \
  -DOPENSSL_BN_ASM_MONT \
  -DSHA1_ASM \
  -DSHA256_ASM \
  -DSHA512_ASM \

arm_src_files := \
  crypto/aes/asm/aes-armv4.S \
  crypto/bn/asm/armv4-gf2m.S \
  crypto/bn/asm/armv4-mont.S \
  crypto/modes/asm/ghash-armv4.S \
  crypto/sha/asm/sha1-armv4-large.S \

arm_exclude_files := \
  crypto/aes/aes_core.c \

aarch64_c_flags := \
  -DOPENSSL_NO_ASM \

aarch64_src_files :=

aarch64_exclude_files :=

x86_c_flags := \
  -DAES_ASM \
  -DDES_PTR \
  -DDES_RISC1 \
  -DDES_UNROLL \
  -DGHASH_ASM \
  -DMD5_ASM \
  -DOPENSSL_BN_ASM_GF2m \
  -DOPENSSL_BN_ASM_MONT \
  -DOPENSSL_BN_ASM_PART_WORDS \
  -DOPENSSL_CPUID_OBJ \
  -DSHA1_ASM \
  -DSHA256_ASM \
  -DSHA512_ASM \

x86_src_files := \
  crypto/aes/asm/aes-586.S \
  crypto/aes/asm/aesni-x86.S \
  crypto/aes/asm/vpaes-x86.S \
  crypto/bn/asm/bn-586.S \
  crypto/bn/asm/co-586.S \
  crypto/bn/asm/x86-gf2m.S \
  crypto/bn/asm/x86-mont.S \
  crypto/modes/asm/ghash-x86.S \
  crypto/sha/asm/sha1-586.S \
  crypto/x86cpuid.S \

x86_exclude_files := \
  crypto/aes/aes_cbc.c \
  crypto/aes/aes_core.c \
  crypto/bf/bf_enc.c \
  crypto/bn/bn_asm.c \
  crypto/des/des_enc.c \
  crypto/des/fcrypt_b.c \
  crypto/mem_clr.c \

x86_64_c_flags := \
  -DAES_ASM \
  -DDES_PTR \
  -DDES_RISC1 \
  -DDES_UNROLL \
  -DGHASH_ASM \
  -DMD5_ASM \
  -DOPENSSL_BN_ASM_GF2m \
  -DOPENSSL_BN_ASM_MONT \
  -DOPENSSL_CPUID_OBJ \
  -DSHA1_ASM \
  -DSHA256_ASM \
  -DSHA512_ASM \

x86_64_src_files := \
  crypto/aes/asm/aes-x86_64.S \
  crypto/aes/asm/aesni-sha1-x86_64.S \
  crypto/aes/asm/aesni-x86_64.S \
  crypto/aes/asm/bsaes-x86_64.S \
  crypto/aes/asm/vpaes-x86_64.S \
  crypto/bn/asm/modexp512-x86_64.S \
  crypto/bn/asm/x86_64-gcc.c \
  crypto/bn/asm/x86_64-gf2m.S \
  crypto/bn/asm/x86_64-mont.S \
  crypto/bn/asm/x86_64-mont5.S \
  crypto/md5/asm/md5-x86_64.S \
  crypto/modes/asm/ghash-x86_64.S \
  crypto/sha/asm/sha1-x86_64.S \
  crypto/x86_64cpuid.S \

x86_64_exclude_files := \
  crypto/aes/aes_cbc.c \
  crypto/aes/aes_core.c \
  crypto/bn/bn_asm.c \
  crypto/mem_clr.c \

mips_c_flags := \
  -DAES_ASM \
  -DOPENSSL_BN_ASM_MONT \
  -DSHA1_ASM \
  -DSHA256_ASM \

mips_src_files := \
  crypto/aes/asm/aes-mips.S \
  crypto/bn/asm/bn-mips.S \
  crypto/bn/asm/mips-mont.S \
  crypto/sha/asm/sha1-mips.S \

mips_exclude_files := \
  crypto/aes/aes_core.c \
  crypto/bn/bn_asm.c \

target_arch := $(TARGET_ARCH)
ifeq ($(target_arch)-$(TARGET_HAS_BIGENDIAN),mips-true)
target_arch := unknown_arch
endif

target_c_flags    := $(common_c_flags) $($(target_arch)_c_flags) $(local_c_flags)
target_c_includes := $(local_c_includes)
target_src_files  := $(common_src_files) $($(target_arch)_src_files)
target_src_files  := $(filter-out $($(target_arch)_exclude_files), $(target_src_files))

local_additional_dependencies += $(LOCAL_PATH)/Crypto-config.mk

