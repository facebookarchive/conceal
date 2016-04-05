We currently use openssl-1.0.2g

### Sources
Repo: **git://git.openssl.org/openssl.git**  
Tag: **OpenSSL_1_0_2g**

### Builds For ARCHS:
  * arm64-v8a
  * armeabi
  * armeabi-v7a
  * x86
  * x86_64

Read more about available ARCHS [here](https://developer.android.com/ndk/guides/standalone_toolchain.html)

### Environment
Requires `ANDROID_NDK` to be set  
Example:  
`export ANDROID_NDK=/opt/android-ndk-r11c`

### Usage
`make`

### Output
`make` generates `libcrypto.a` for each ARCH and saves them to `openssl/$ARCH/libcrypto.a`
