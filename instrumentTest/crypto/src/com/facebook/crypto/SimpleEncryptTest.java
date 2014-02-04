package com.facebook.crypto;

import android.annotation.TargetApi;
import android.os.Build;
import android.test.InstrumentationTestCase;
import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.exception.KeyChainException;
import com.facebook.crypto.keychain.KeyChain;
import com.facebook.crypto.util.NativeCryptoLibrary;
import com.facebook.crypto.util.SystemNativeCryptoLibrary;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

@TargetApi(Build.VERSION_CODES.GINGERBREAD)
public class SimpleEncryptTest extends InstrumentationTestCase {

  private Crypto mCrypto;
  private NativeCryptoLibrary mNativeCryptoLibrary;
  private byte[] mData;
  private byte[] mIV;
  private byte[] mKey;

  protected void setUp() throws Exception {
    super.setUp();
    mNativeCryptoLibrary = new SystemNativeCryptoLibrary();
    KeyChain keyChain = new FakeKeyChain();
    mKey = keyChain.getCipherKey();
    mIV = keyChain.getNewIV();
    mCrypto = new Crypto(keyChain, mNativeCryptoLibrary);
    mData = new byte[CryptoTestUtils.NUM_DATA_BYTES];
  }

  public void testCompatibleWithBouncycastle() throws Exception {
    byte[] opensslEncrypted = mCrypto.encrypt(mData, new Entity(CryptoTestUtils.ENTITY_NAME));

    Entity entity = new Entity(CryptoTestUtils.ENTITY_NAME);
    byte[] aadData = CryptoSerializerHelper.computeBytesToAuthenticate(
        entity.getBytes(),
        VersionCodes.CIPHER_SERALIZATION_VERSION,
        VersionCodes.CIPHER_ID);
    BouncyCastleHelper.Result result = BouncyCastleHelper.bouncyCastleEncrypt(mData,
        mKey,
        mIV,
        aadData);

    byte[] opensslTag = CryptoSerializerHelper.tag(opensslEncrypted);
    byte[] opensslCipherText = CryptoSerializerHelper.cipherText(opensslEncrypted);

    assertTrue(
        CryptoTestUtils.ENCRYPTED_DATA_DOES_NOT_MATCH,
        Arrays.equals(result.cipherText, opensslCipherText)
    );
    assertTrue(CryptoTestUtils.TAG_DOES_NOT_MATCH, Arrays.equals(result.tag, opensslTag));
  }

  public void testWriteData() throws Exception {
    byte[] cipherText = mCrypto.encrypt(mData, new Entity(CryptoTestUtils.ENTITY_NAME));
    byte[] encryptedData = CryptoSerializerHelper.cipherText(cipherText);

    assertTrue(CryptoTestUtils.ENCRYPTED_DATA_NULL, encryptedData != null);
    assertTrue(CryptoTestUtils.ENCRYPTED_DATA_OF_DIFFERENT_LENGTH,
        encryptedData.length == mData.length);
    assertTrue(CryptoTestUtils.DATA_IS_NOT_ENCRYPTED, !Arrays.equals(mData, encryptedData));
  }

  public void testMatchesWithStreamingAPI() throws KeyChainException, CryptoInitializationException, IOException {
    byte[] cipherText = mCrypto.encrypt(mData, new Entity(CryptoTestUtils.ENTITY_NAME));
    ByteArrayOutputStream cipherStream = new ByteArrayOutputStream();
    OutputStream outputStream = mCrypto.getCipherOutputStream(
        cipherStream,
        new Entity(CryptoTestUtils.ENTITY_NAME));
    outputStream.write(mData);
    outputStream.close();
    assertTrue(CryptoTestUtils.ENCRYPTED_DATA_IS_DIFFERENT, Arrays.equals(cipherStream.toByteArray(), cipherText));
  }
}
