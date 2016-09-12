package javax.crypto.des.impl;

import javax.crypto.des.TripleDESEncrypterService;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author Thomas Weckert
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = { "/TripleDESEncrypterService.xml" })
public class TripleDESEncrypterServiceImplTest {
	
	@Autowired private TripleDESEncrypterService tripleDESEncrypterService;

	@Test
	public void testEncryptDecrypt() throws Exception {

		// GIVEN
		String inputStr = "Hello, world! 0123456789 öäüß !\"$%&/()=? ;:_'*";

		// WHEN
		String encrypted = tripleDESEncrypterService.encrypt(inputStr, "UTF-8");
		String decrypted = tripleDESEncrypterService.decrypt(encrypted, "UTF-8");

		// THEN
		Assert.assertTrue(decrypted.equals(inputStr));
		Assert.assertTrue(!encrypted.equals(inputStr));
		Assert.assertTrue(!decrypted.equals(encrypted));
	}

}
