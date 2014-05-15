##What is Conceal?##
Conceal provides a set of Java APIs to perform cryptography on Android. 
It was designed to be able to encrypt large files on disk in a fast and 
memory efficient manner. 

The major target for this project is typical Android devices which run old 
Android versions, have low memory and slower processors.

Unlike other libraries, which provide a Smorgasbord of encryption algorithms 
and options, Conceal prefers to abstract this choice and use sane defaults. 
Thus Conceal is not a general purpose crypto library, however it aims to provide 
useful functionality.

##Quick start##

####Building Conceal####
```bash
buck build :crypto
```

###Using Maven###
Avaiable on maven central under **com.facebook.conceal:conceal** as an AAR package.

####Running Benchmarks####
```bash
./benchmarks/run \
  benchmarks/src/com/facebook/crypto/benchmarks/CipherReadBenchmark.java \
  -- -Dsize=102400
```

This script runs vogar with caliper benchmarks.
You can also specify all the options caliper provides.

######An aside on KitKat######
> Conceal predates Jellybean 4.3. On KitKat, Android changed the provider for 
> cryptographic algorithms to OpenSSL. The default Cipher stream however still 
> does not perform well. When replaced with our Cipher stream 
> (see BetterCipherInputStream), the default implementation is competitive against 
> Conceal. On older phones, Conceal is faster than the system provided libraries.

####Running unit tests####
```bash
buck test javatests/com/facebook/crypto:crypto
```

####Running integration tests####
```bash
./instrumentTest/crypto/run
```

Since Conceal uses native libraries, the only way to run a test on the entire
encryption process is using integration tests.

##Usage##

####Encryption###
```java
// Creates a new Crypto object with default implementations of 
// a key chain as well as native library.
Crypto crypto = new Crypto(
  new SharedPrefsBackedKeyChain(context),
  new SystemNativeCryptoLibrary());

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
  entity);

// Write plaintext to it.
outputStream.write(plainText);
outputStream.close();
```

####Decryption####
```java
// Get the file to which ciphertext has been written.
FileInputStream fileStream = new FileInputStream(file);

// Creates an input stream which decrypts the data as
// it is read from it.
InputStream inputStream = crypto.getCipherInputStream(
  fileStream,
  entity);

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
byte[] cipherText = crypto.encrypt(plainText);

byte[] plainText = crypto.decrypt(cipherText);
```

####Integrity####
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

