We currently use openssl-1.0.1e

1. Checkout openssl
```bash
git clone git://git.openssl.org/openssl.git
cd openssl
```

2. Checkout openssl to commit 4ac0329582829f5378d8078c8d314ad37db87736
```bash
git checkout 4ac0329582829f5378d8078c8d314ad37db87736
```

Our patches are layered on this commit. It might work from HEAD, however 
this is the safest bet.

3. Apply the patches in order
```bash
git apply 0001-modifications-to-openssl-1.0.2.patch
```

4. Make an ndk toolchain
```bash
/build/tools/make-standalone-toolchain.sh --platform=android-19 --install-dir=/tmp/toolchain --toolchain=arm-linux-androideabi-4.8
```

5. Add the toolchain to your path
```bash
export PATH=/tmp/toolchain/arm-linux-androideabi/bin:$PATH
```

6. Configure and compile openssl
```bash
./conf && make depend && make build_crypto
```

The libs will be located in libcrypto.a, copy that over to the native/third-party/openssl folder.

