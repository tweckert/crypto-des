package javax.crypto.des;

public interface TripleDESEncrypterService {

	/**
	 * Encrypts a string.
	 *
	 * @param str the input string to be encrypted
	 * @param charEncoding the character encoding of the input string
	 * @return the encrypted string
	 * @throws Exception if something goes wrong
	 */
	String encrypt(String str, String charEncoding) throws Exception;

	/**
	 * Encrypts a byte array.
	 *
	 * @param bytes the byte array to be encrypted
	 * @return the encrypted byte array
	 * @throws Exception if something goes wrong
	 */
	byte[] encrypt(byte[] bytes) throws Exception;

	/**
	 * Decrypts a string.
	 *
	 * @param str the input string to be decrypted
	 * @param charEncoding the character encoding of the output string
	 * @return the decrypted string
	 * @throws Exception if something goes wrong
	 */
	String decrypt(String str, String charEncoding) throws Exception;

	/**
	 * Decrypts a byte array.
	 *
	 * @param bytes the byte array to be decrypted
	 * @return the decrypted byte array
	 * @throws Exception if something goes wrong
	 */
	byte[] decrypt(byte[] bytes) throws Exception;

}