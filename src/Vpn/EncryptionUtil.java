package Vpn;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class EncryptionUtil {
    public static byte[] encrypt(byte[] plaintext, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // AES encryption with CBC mode
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(byte[] ciphertext, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // AES decryption with CBC mode
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(ciphertext);
    }

    public static IvParameterSpec generateIV() {
        byte[] iv = new byte[16]; // 16-byte IV for AES
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}
