## What is Conceal? [![Build Status](https://travis-ci.org/facebook/conceal.svg?branch=master)](https://travis-ci.org/facebook/conceal)

Conceal provides a set of Java APIs to perform cryptography on Android. 
It was designed to be able to encrypt large files on disk in a fast and 
memory efficient manner. 

The major target for this project is typical Android devices which run old 
Android versions, have low memory and slower processors.

Unlike other libraries, which provide a Smorgasbord of encryption algorithms 
and options, Conceal prefers to abstract this choice and use sane defaults. 
Thus Conceal is not a general purpose crypto library, however it aims to provide 
useful functionality.

***Upgrading version?*** Check the [Upgrade notes](#upgrade-notes) for key compatibility!

#### IMPORTANT: Initializing the library loader

Since v2.0.+ (2017-06-27) you will need to initialize the native library loader.
This step is needed because the library loader uses the context.
The highly suggested way to do it is in the application class onCreate method like this:

```java
import com.facebook.soloader.SoLoader;
public class MyApplication extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        SoLoader.init(this, false);
    }
}
```

## Quick start

#### Setup options

1. **Use Maven Central**: Available on maven central under **com.facebook.conceal:conceal:2.0.1@aar** as an AAR package.
If you use Android Studio and select the library using the UI, **make sure** to change `build.gradle` **to include the `@aar` suffix**. Otherwise the library won't be included.

2. **Build using gradle**

```bash
./gradlew build
```

It uses gradlew so it takes care of downloading Gradle and all the dependencies it needs.
Output will be in `/build/outputs/aar/` directory.

3. **Use prebuilt binaries**: http://facebook.github.io/conceal/documentation/. (linked documentation needs update)

###### An aside on KitKat
> Conceal predates Jellybean 4.3. On KitKat, Android changed the provider for 
> cryptographic algorithms to OpenSSL. The default Cipher stream however still 
> does not perform well. When replaced with our Cipher stream 
> (see BetterCipherInputStream), the default implementation is competitive against 
> Conceal. On older phones, Conceal is faster than the system provided libraries.

#### Re-build OpenSSL library

You can run make from the openssl directory. It will download the code and copile the libraries for each architecture.

```bash
# go to /third-party/openssl
make
```

#### Before running any test!

Test uses BUCK build tool. BUCK uses the source code for OpenSSL. If you didn't already rebuilt OpenSSL form scrach (previous item) then
run this:

```bash
# go to /third-party/openssl
make clone
```

That will download the OpenSSL code to a subdirectory.

#### Running unit tests
```bash
# C++ tests
buck test :cpp
```

#### Running integration tests
```bash
# Emulator/device tests
./instrumentTest/crypto/run
```

Since Conceal uses native libraries, the only way to run a test on the entire
encryption process is using integration tests.

#### Running Benchmarks
```bash
./benchmarks/run \
  benchmarks/src/com/facebook/crypto/benchmarks/CipherReadBenchmark.java \
  -- -Dsize=102400
```

This script runs vogar with caliper benchmarks.
You can also specify all the options caliper provides.

## Usage

#### Entity and keys

**Entity:** this is a not-secret identifier of your data. It's used for integrity check purposes (to know that the content has not been tampered) and also to verify it was not swapped with another valid encrypted content/file.

**Key:** the key is provided by the KeyChain implementation passed to the Crypto object. So each time a new encryption is requested, the key is requested to the KeyChain. The key is generated randomly the first time on demand. You might change the implementation by we strongly suggest to generate a random value. If the encryption key needs for some reason to be based on a text password, you can try using the PasswordBasedKeyGenerator object.

#### Encryption
```java
// Creates a new Crypto object with default implementations of a key chain
KeyChain keyChain = new SharedPrefsBackedKeyChain(context, CryptoConfig.KEY_256);
Crypto crypto = AndroidConceal.get().createDefaultCrypto(keyChain);

// Check for whether the crypto functionality is available
// This might fail if Android does not load libaries correctly.
if (!crypto.isAvailable()) {
  return;
}

OutputStream fileStream = new BufferedOutputStream(
  new FileOutputStream(file));

// Creates an output stream which encrypts the data as
// it is written to it and writes it out to the file.
OutputStream outputStream = crypto.getCipherOutputStream(
  fileStream,
  Entity.create("entity_id"));

// Write plaintext to it.
outputStream.write(plainText);
outputStream.close();
```

#### Decryption
```java
// Get the file to which ciphertext has been written.
FileInputStream fileStream = new FileInputStream(file);

// Creates an input stream which decrypts the data as
// it is read from it.
InputStream inputStream = crypto.getCipherInputStream(
  fileStream,
  Entity.create("entity_id"));

// Read into a byte array.
int read;
byte[] buffer = new byte[1024];

// You must read the entire stream to completion.
// The verification is done at the end of the stream.
// Thus not reading till the end of the stream will cause
// a security bug. For safety, you should not
// use any of the data until it's been fully read or throw
// away the data if an exception occurs.
while ((read = inputStream.read(buffer)) != -1) {
  out.write(buffer, 0, read);
}

inputStream.close();
```

If you don't have a lot of data to encrypt, you could
use the convenience functions:

```java
byte[] cipherText = crypto.encrypt(plainText, Entity.create("mytext"));

byte[] plainText = crypto.decrypt(cipherText, Entity.create("mytext"));
```

#### Integrity
```java
OutputStream outputStream = crypto.getMacOutputStream(fileStream, entity);
outputStream.write(plainTextBytes);
outputStream.close();

InputStream inputStream = crypto.getMacInputStream(fileStream, entity);

// Will throw an exception if mac verification fails.
// You must read the entire stream to completion.
// The verification is done at the end of the stream.
// Thus not reading till the end of the stream will cause
// a security bug. For safety, you should not
// use any of the data until it's been fully read or throw
// away the data if an exception occurs.
while((read = inputStream.read(buffer)) != -1) {
  out.write(buffer, 0, read);
}
inputStream.close();
```

### Upgrade notes

Starting with v1.1 recommended encryption will use a 256-bit key (instead of 128-bit). This means stronger security.
You should use this default.

If you need to read from an existing file, you still will need 128-bit encryption. You can use the old way of creating `Crypto` objects as it preserves its 128-bit behavior. Although ideally you should re-encrypt that content with a 256-bit key.

Also there's an improved way of creating Entity object which is platform independent. It's strongly recommended for new encrypted items although you need to stick to the old way for already encrypted content.

#### Existing code still with 128-bit keys and old Entity (deprecated)

```java
// this constructor creates a key chain that produces 128-bit keys
KeyChain keyChain = new SharedPrefsBackedKeyChain(context);
// this constructor creates a crypto that uses  128-bit keys
Crypto crypto = new Crypto(keyChain, library);
Entity entity = new Entity(someStringId);
```

#### New code using 256-keys and Entity.create

We recommend the use of the factory class `AndroidConceal`.

```java
// explicitely create 256-bit key chain
KeyChain keyChain = new SharedPrefsBackedKeyChain(context, CryptoConfig.KEY_256);
// create the default crypto (expects 256-bit key)
AndroidConceal.get().createDefaultCrypto(keyChain);
// factory class also has explicit methods: createCrypto128Bits and ceateCrypto256Bits if desired.
Entity entity = Entity.create(someStringId);
```

## Troubleshooting

#### I'm getting NoSuchFieldError on runtime

If you hit an error on runtime and it says something similar to:

````
java.lang.NoSuchFieldError: no field with name='mCtxPtr' signature='J' in class Lcom/facebook/crypto/cipher/NativeGCMCipher;
````

This happens because native code needs to refer to Java fields/methods. For doing so it uses typical JNI functions which receive the name and signature. At the same time tools like proguard trim off or rename class members in order to get smaller executables. Normally this process is run on release versions. When native code request the member, it's not present anymore.

To avoid this kind of problems exceptions can be defined. You will need to configure proguard with the rules defined in ``proguard_annotations.pro``. You can use the file as is, or you can include its content in your own proguard configuration file.
