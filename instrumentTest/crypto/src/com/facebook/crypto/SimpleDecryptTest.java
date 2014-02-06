package com.facebook.crypto;

import android.annotation.TargetApi;
import android.os.Build;
import android.test.InstrumentationTestCase;
import com.facebook.crypto.cipher.NativeGCMCipher;
import com.facebook.crypto.keychain.KeyChain;
import com.facebook.crypto.util.NativeCryptoLibrary;
import com.facebook.crypto.util.SystemNativeCryptoLibrary;

import java.io.*;
import java.util.Arrays;

@TargetApi(Build.VERSION_CODES.GINGERBREAD)
public class SimpleDecryptTest extends InstrumentationTestCase {

  private Crypto mCrypto;
  private NativeCryptoLibrary mNativeCryptoLibrary;
  private byte[] mData;
  private byte[] mCipheredData;
  private byte[] mIV;
  private byte[] mKey;

  protected void setUp() throws Exception {
    super.setUp();
    mNativeCryptoLibrary = new SystemNativeCryptoLibrary();
    KeyChain keyChain = new FakeKeyChain();
    mCrypto = new Crypto(keyChain, mNativeCryptoLibrary);
    mIV = keyChain.getNewIV();
    mKey = keyChain.getCipherKey();

    // Encrypt some data before each test.
    mData = new byte[CryptoTestUtils.NUM_DATA_BYTES];
    ByteArrayOutputStream cipherOutputStream = new ByteArrayOutputStream();

    OutputStream outputStream = mCrypto.getCipherOutputStream(
        cipherOutputStream,
        new Entity(CryptoTestUtils.ENTITY_NAME));
    outputStream.write(mData);
    outputStream.close();

    mCipheredData = cipherOutputStream.toByteArray();
  }

  public void testDecryptionFailsOnIncorrectEntity() throws Exception {
    try {
      mCrypto.decrypt(mCipheredData, new Entity(CryptoTestUtils.FAKE_ENTITY_NAME));
    } catch (IOException e) {
      return;
    }
    fail(CryptoTestUtils.EXCEPTION_EXPECTED);
  }

  public void testDecryptionFailsOnIncorrectTag() throws Exception {
    byte[] fakeTag = new byte[NativeGCMCipher.TAG_LENGTH];
    Arrays.fill(fakeTag, (byte) CryptoTestUtils.KEY_BYTES);

    // Overwrite the tag bytes.
    System.arraycopy(fakeTag,
        0,
        mCipheredData,
        mCipheredData.length - NativeGCMCipher.TAG_LENGTH,
        NativeGCMCipher.TAG_LENGTH);
    try {
      mCrypto.decrypt(mCipheredData, new Entity(CryptoTestUtils.ENTITY_NAME));
    } catch (IOException e) {
      return;
    }
    fail(CryptoTestUtils.EXCEPTION_EXPECTED);
  }

  public void testDecryptionFailsOnIncorrectData() throws Exception {
    byte[] fakeData = new byte[CryptoTestUtils.NUM_DATA_BYTES];
    Arrays.fill(fakeData, (byte) CryptoTestUtils.KEY_BYTES);
    byte[] realTag = CryptoSerializerHelper.tag(mCipheredData);
    byte[] tamperedCipherData = CryptoSerializerHelper.createCipheredData(mIV,
        fakeData,
        realTag);

    try {
      mCrypto.decrypt(tamperedCipherData, new Entity(CryptoTestUtils.ENTITY_NAME));
    } catch (IOException e) {
      return;
    }
    fail(CryptoTestUtils.EXCEPTION_EXPECTED);
  }

  public void testDecryptValidData() throws Exception {
    byte[] plainText = mCrypto.decrypt(mCipheredData, new Entity(CryptoTestUtils.ENTITY_NAME));
    assertTrue(CryptoTestUtils.DECRYPTED_DATA_IS_DIFFERENT, Arrays.equals(mData, plainText));
  }

  public void testCompatibleWithBouncyCastle() throws Exception {
    Entity entity = new Entity(CryptoTestUtils.ENTITY_NAME);
    byte[] aadData = CryptoSerializerHelper.computeBytesToAuthenticate(entity.getBytes(),
        VersionCodes.CIPHER_SERALIZATION_VERSION,
        VersionCodes.CIPHER_ID);
    BouncyCastleHelper.Result result = BouncyCastleHelper.bouncyCastleEncrypt(mData,
        mKey,
        mIV,
        aadData);

    byte[] cipheredData = CryptoSerializerHelper.createCipheredData(mIV, result.cipherText, result.tag);

    byte[] decryptedData = mCrypto.decrypt(cipheredData, new Entity(CryptoTestUtils.ENTITY_NAME));
    assertTrue(CryptoTestUtils.DECRYPTED_DATA_IS_DIFFERENT, Arrays.equals(mData, decryptedData));
  }
}
