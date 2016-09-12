package javax.crypto.des.impl;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.des.TripleDESEncrypterService;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.stereotype.Service;

/**
 * A service to encrypte/decrypt strings and byte arrays using symmetric triple DES.
 *
 * Triple DES uses 128-bit keys with 112 effective bits. CBC (Cipher Block Chaining) is used
 * as the block mode, where the result of processing the current block is used in processing
 * the next block.
 * 
 * @author Thomas Weckert
 */
@Scope(value = BeanDefinition.SCOPE_SINGLETON, proxyMode = ScopedProxyMode.INTERFACES)
@Service("TripleDESEncrypterService")
public class TripleDESEncrypterServiceImpl implements InitializingBean, TripleDESEncrypterService {

	@Value("${TripleDESEncrypterService.key}") private String key;
	private byte[] keyBytes;
    private DESedeKeySpec keySpec;
    private SecretKeyFactory secretKeyFactory;
    private SecretKey secretKey;
    private Cipher encryptionCipher;
    private Cipher decryptionCipher;

	@Override
	public void afterPropertiesSet() throws Exception {

        // create an array to hold the key
        this.keyBytes = key.getBytes();

        // create a DESede key spec from the key
        this.keySpec = new DESedeKeySpec(keyBytes);

        // get the secret key factor for generating triple DES (aka DESede) keys
        this.secretKeyFactory = SecretKeyFactory.getInstance("DESede");

        // generate a DESede SecretKey object
        this.secretKey = this.secretKeyFactory.generateSecret(keySpec);

        // create a DESede Cipher
        this.encryptionCipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        this.decryptionCipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");

        // create an initialization vector (necessary for CBC mode)
        IvParameterSpec IvParameters = new IvParameterSpec(new byte[] {
                12, 34, 56, 78, 90, 87, 65, 43
        });

        // initialize two ciphers to encrypt and decrypt data
        this.encryptionCipher.init(Cipher.ENCRYPT_MODE, this.secretKey, IvParameters);
        this.decryptionCipher.init(Cipher.DECRYPT_MODE, this.secretKey, IvParameters);
    }

    @Override
	public String encrypt(String str, String charEncoding) throws Exception {

        byte[] bytes = str.getBytes(charEncoding);
        byte[] encrypted = encrypt(bytes);

        // to have the encrypted byte array as a string, it is necessary to convert
        // the byte array to hexadecimal. this is because String does its own
        // character encoding. a byte array to construct a string and the byte
        // array that you get from a string are not necessarily equal.
        // strings are evil!
        return new sun.misc.BASE64Encoder().encode(encrypted);
    }

    @Override
	public byte[] encrypt(byte[] bytes) throws Exception {

        if (bytes == null) {

            return null;
        }

        return encryptionCipher.doFinal(bytes);
    }

    @Override
	public String decrypt(String str, String charEncoding) throws Exception {

        byte[] bytes = new sun.misc.BASE64Decoder().decodeBuffer(str);
        byte[] decrypted = decrypt(bytes);

        return new String(decrypted, charEncoding);
    }

    @Override
	public byte[] decrypt(byte[] bytes) throws Exception {

        if (bytes == null) {

            return null;
        }

        return decryptionCipher.doFinal(bytes);
    }

}
