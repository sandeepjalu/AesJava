import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

/**
 * 
 */

/**
 * @author sandeep
 *
 */
public class EncTest {

	/**
	 * @param args
	 */
	public static void main(String args[]) throws Exception{

		/*String password = "aeae08e9-2f69-44bc-9ef1-fe629c18d362";
	    String salt = "f8c6b811f4e44809b4a3045286251971";
	    String iv = "cc96e7f8c89652fe5d3eea4c8c76d213";
	    String encrypted = "wO7lXB6QFSr8jDaIEAA3ug==";*/
		String password = "aeae08e9-2f69-44bc-9ef1-fe629c18d362";
	    String salt = "4acfedc7dc72a9003a0dd721d7642bde";
	    String iv = "69135769514102d0eded589ff874cacd";
	    String encrypted = "2+P8JMKXpQchyP8IzfltfQ==";
	    
	    byte[] saltBytes = hexStringToByteArray(salt);
	    byte[] ivBytes = hexStringToByteArray(iv);
	    IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);        
	    SecretKeySpec sKey = (SecretKeySpec) generateKeyFromPassword(password, saltBytes);
	    System.out.println( decrypt( encrypted , sKey ,ivParameterSpec));
	    System.out.println( encrypt( "Hello_World KASDKSKD" , sKey ,ivParameterSpec));
	}

	public static SecretKey generateKeyFromPassword(String password, byte[] saltBytes) throws GeneralSecurityException {

	    KeySpec keySpec = new PBEKeySpec(password.toCharArray(), saltBytes, 100, 128);
	    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
	    SecretKey secretKey = keyFactory.generateSecret(keySpec);

	    return new SecretKeySpec(secretKey.getEncoded(), "AES");
	}

	public static byte[] hexStringToByteArray(String s) {

	    int len = s.length();
	    byte[] data = new byte[len / 2];

	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                + Character.digit(s.charAt(i+1), 16));
	    }

	    return data;
	}

	public static String decrypt(String encryptedData, SecretKeySpec sKey, IvParameterSpec ivParameterSpec) throws Exception { 

	    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
	    c.init(Cipher.DECRYPT_MODE, sKey, ivParameterSpec);
	    byte[] decordedValue = Base64.decodeBase64(encryptedData);// new BASE64Decoder().decodeBuffer(encryptedData);
	    byte[] decValue = c.doFinal(decordedValue);
	    String decryptedValue = new String(decValue);

	    return decryptedValue;
	}

	public static String encrypt(String msg, SecretKeySpec sKey, IvParameterSpec ivParameterSpec) throws Exception { 

	    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
	    c.init(Cipher.ENCRYPT_MODE, sKey, ivParameterSpec);
	    //byte[] encodedValue = msg.getBytes("UTF-8");
	    //byte[] encodedValue = Base64.decodeBase64(msg);// new BASE64Decoder().decodeBuffer(encryptedData);
	    String encM = Base64.encodeBase64String(c.doFinal(msg.getBytes("UTF-8")));
	    System.out.println(encM);
	    //byte[] encValue = c.doFinal(encodedValue);
//	    String encryptedValue = new String(encValue,"UTF-8");

	    return encM;
	}
}
