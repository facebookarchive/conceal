RANDOM_SRCS = [
    "java/com/facebook/android/crypto/keychain/SecureRandomFix.java",
]

android_aar(
    name = "aar",
    manifest_skeleton = "AndroidManifest.xml",
    deps = [
        ":conceal",
        ":jni",
    ],
)

# To use (for now) in instrumentation tests
# which needs the full library, but it's ran with BUCK
android_prebuilt_aar(
    name = "prebuilt_aar",
    aar = "build/outputs/aar/conceal-debug.aar",
    visibility = ['PUBLIC'],
)

android_library(
    name = "conceal",
    srcs = glob(
        ["java/com/facebook/android/**/*.java"],
        excludes = RANDOM_SRCS,
    ),
    exported_deps = [
        ":conceal-random",
        ":libconceal",
    ],
    visibility = [
        "PUBLIC",
    ],
)

java_library(
    name = "libconceal",
    srcs = glob([
        "java/com/facebook/cipher/**/*.java",
        "java/com/facebook/crypto/**/*.java",
        "java/com/facebook/proguard/**/*.java",
    ]),
    proguard_config = "proguard_annotations.pro",
    visibility = [
        "PUBLIC",
    ],
    deps = [
        ":cpp",
        ":jni",
        "//first-party/fbjni/java/com/facebook/jni:jni",
    ],
)

android_library(
    name = "conceal-random",
    srcs = RANDOM_SRCS,
    visibility = [
        "PUBLIC",
    ],
    deps = [
    ],
)

cxx_library(
    name = "cpp",
    srcs = [
        "native/cpp/Cipher.cpp",
        "native/cpp/CryptoConfig.cpp",
        "native/cpp/Decrypt.cpp",
        "native/cpp/DecryptStream.cpp",
        "native/cpp/Encrypt.cpp",
        "native/cpp/EncryptStream.cpp",
        "native/cpp/MacConfig.cpp",
        "native/cpp/MacDecoder.cpp",
        "native/cpp/MacEncoder.cpp",
        "native/cpp/PBKDF2.cpp",
        "native/cpp/SliceMethods.cpp",
        "native/cpp/TailBuffer.cpp",
        "native/cpp/TransformBuffer.cpp",
        "native/cpp/WithState.cpp",
    ],
    compiler_flags = [
        "-Wall",
        "-Werror",
        "-std=gnu++1y",
        "-fexceptions",
    ],
    exported_headers = {
        "conceal/Buffer.h": "native/cpp/Buffer.h",
        "conceal/Cipher.h": "native/cpp/Cipher.h",
        "conceal/CryptoConfig.h": "native/cpp/CryptoConfig.h",
        "conceal/CryptoException.h": "native/cpp/CryptoException.h",
        "conceal/Decrypt.h": "native/cpp/Decrypt.h",
        "conceal/DecryptStream.h": "native/cpp/DecryptStream.h",
        "conceal/Encrypt.h": "native/cpp/Encrypt.h",
        "conceal/EncryptStream.h": "native/cpp/EncryptStream.h",
        "conceal/KeyChain.h": "native/cpp/KeyChain.h",
        "conceal/MacConfig.h": "native/cpp/MacConfig.h",
        "conceal/MacDecoder.h": "native/cpp/MacDecoder.h",
        "conceal/MacEncoder.h": "native/cpp/MacEncoder.h",
        "conceal/PBKDF2.h": "native/cpp/PBKDF2.h",
        "conceal/Slice.h": "native/cpp/Slice.h",
        "conceal/TailBuffer.h": "native/cpp/TailBuffer.h",
        "conceal/TransformBuffer.h": "native/cpp/TransformBuffer.h",
        "conceal/WithState.h": "native/cpp/WithState.h",
    },
    header_namespace = "",
    headers = [
        "native/cpp/Buffer.h",
        "native/cpp/Cipher.h",
        "native/cpp/CryptoConfig.h",
        "native/cpp/CryptoException.h",
        "native/cpp/Decrypt.h",
        "native/cpp/DecryptStream.h",
        "native/cpp/Encrypt.h",
        "native/cpp/EncryptStream.h",
        "native/cpp/KeyChain.h",
        "native/cpp/MacConfig.h",
        "native/cpp/MacDecoder.h",
        "native/cpp/MacEncoder.h",
        "native/cpp/PBKDF2.h",
        "native/cpp/Slice.h",
        "native/cpp/SliceMethods.h",
        "native/cpp/TailBuffer.h",
        "native/cpp/TransformBuffer.h",
        "native/cpp/WithState.h",
    ],
    soname = "libconcealcpp.$(ext)",
    visibility = [
        'PUBLIC',
    ],
    deps = [
        "//third-party/openssl:crypto",
    ],
)

cxx_library(
    name = "jni",
    srcs = [
        "native/jni/CipherHybrid.cpp",
        "native/jni/DecryptHybrid.cpp",
        "native/jni/EncryptHybrid.cpp",
        "native/jni/JKeyChain.cpp",
        "native/jni/JavaArrays.cpp",
        "native/jni/KeyChainFromJava.cpp",
        "native/jni/MacDecoderHybrid.cpp",
        "native/jni/MacEncoderHybrid.cpp",
        "native/jni/OnLoad.cpp",
        "native/jni/PBKDF2Hybrid.cpp",
    ],
#    allow_jni_merging = True,
    compiler_flags = [
        "-Wall",
        "-Werror",
        "-std=gnu++1y",
        "-fexceptions",
    ],
    exported_headers = {
        "conceal/jni/JKeyChain.h": "native/jni/JKeyChain.h",
        "conceal/jni/KeyChainFromJava.h": "native/jni/KeyChainFromJava.h",
        "conceal/jni/CipherHybrid.h": "native/jni/CipherHybrid.h",
        "conceal/jni/DecryptHybrid.h": "native/jni/DecryptHybrid.h",
        "conceal/jni/EncryptHybrid.h": "native/jni/EncryptHybrid.h",
        "conceal/jni/PBKDF2Hybrid.h": "native/jni/PBKDF2Hybrid.h",
    },
    header_namespace = "",
    headers = [
        "native/jni/CipherHybrid.h",
        "native/jni/DecryptHybrid.h",
        "native/jni/EncryptHybrid.h",
        "native/jni/JKeyChain.h",
        "native/jni/JavaArrays.h",
        "native/jni/KeyChainFromJava.h",
        "native/jni/MacDecoderHybrid.h",
        "native/jni/MacEncoderHybrid.h",
        "native/jni/PBKDF2Hybrid.h",
    ],
    soname = "libconcealjni.$(ext)",
    visibility = [
        'PUBLIC',
    ],
    deps = [
        ":cpp",
        "//first-party/fbjni/native/fb:jni",
    ],
)

cxx_library(
    name = "cpp_test_helpers",
    srcs = [
        "native/cpp/test/SliceTestHelpers.cpp",
    ],
    compiler_flags = [
        "-Wall",
        "-Werror",
        "-std=gnu++1y",
        "-fexceptions",
    ],
    exported_headers = {
        "conceal/test/SliceTestHelpers.h": "native/cpp/test/SliceTestHelpers.h",
        "conceal/test/TestKeyChain.h": "native/cpp/test/TestKeyChain.h",
    },
    header_namespace = "",
    headers = [
        "native/cpp/test/SliceTestHelpers.h",
        "native/cpp/test/TestKeyChain.h",
    ],
    soname = "libconcealtesthelpers.$(ext)",
    visibility = [
        "PUBLIC",
    ],
    deps = [
        ":cpp",
    ],
)

cxx_test(
    name = "cpp_test",
    compiler_flags = [
        "-Wall",
        "-Werror",
        "-std=gnu++1y",
        "-fexceptions",
    ],
    srcs = [
        "native/cpp/test/BufferTest.cpp",
        "native/cpp/test/CipherTest.cpp",
        "native/cpp/test/DecryptStreamTest.cpp",
        "native/cpp/test/DecryptTest.cpp",
        "native/cpp/test/EncryptStreamTest.cpp",
        "native/cpp/test/EncryptTest.cpp",
        "native/cpp/test/PBKDF2Test.cpp",
        "native/cpp/test/SliceTest.cpp",
        "native/cpp/test/SliceTestHelpers.cpp",
        "native/cpp/test/TailBufferTest.cpp",
        "native/cpp/test/TransformBufferTest.cpp",
    ],
    headers = [
        "native/cpp/test/SliceTestHelpers.h",
        "native/cpp/test/TestKeyChain.h",
    ],
    deps = [
        ":cpp",
        "//third-party/gmock:gtest",
    ],
)
