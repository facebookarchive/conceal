We currently use openssl-1.0.2e

- Checkout openssl
```bash
git clone git://git.openssl.org/openssl.git
cd openssl
```
- Checkout openssl tag OpenSSL_1_0_2e
```bash
git checkout OpenSSL_1_0_2e
```
- Setup your enviornment
``bash
export PATH=/tmp/toolchain:$PATH
```

- Make an ndk toolchain
```bash
$ANDROID_NDK/build/tools/make-standalone-toolchain.sh --install-dir=/tmp/toolchain --arch=<arch>
```

for example for arm, arch is arm, and for arm64 it is arm64
https://developer.android.com/ndk/guides/standalone_toolchain.html

- Configure and compile openssl for for the arc, for example for arm and armv7
```bash
./Configure --cross-compile-prefix=arm-linux-androideabi- android && make depend && make -j20
```
```bash
./Configure --cross-compile-prefix=arm-linux-androideabi- android-armv7 && make depend && make -j20
```

The libs will be located in libcrypto.a, copy that over to the native/third-party/openssl folder.
