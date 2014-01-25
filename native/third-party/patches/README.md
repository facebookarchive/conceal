We currently use openssl-1.0.1e

1. Checkout android openssl
```bash
git clone https://android.googlesource.com/platform/external/openssl
cd openssl
```

2. Checkout openssl to commit af55dde627407177a5aa92a7077672dadab4d587
```bash
git checkout af55dde627407177a5aa92a7077672dadab4d587
```

Our patches are layered on this commit. It might work from HEAD, however 
this is the safest bet.

3. Apply the patches in order
```bash
git apply 0001-Make-openssl-1.0.1e-build.patch
git apply 0002-Make-the-openssl-builds-a-bit-smaller-Part-1.patch
git apply 0003-Make-openssl-smaller-Part-2.patch
```

4. Build openssl
```bash
ndk-build APP_BUILD_SCRIPT=Android.mk APP_ABI=armeabi NDK_PROJECT_PATH=.
```

The libs will be located in libs/{arch}/

