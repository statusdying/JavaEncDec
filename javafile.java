import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AESExample {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    public static byte[] encrypt(byte[] plaintext, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(byte[] ciphertext, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(ciphertext);
    }
    public static byte[] generateKey(int keySizeBits) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[keySizeBits / 8];
        secureRandom.nextBytes(key);
        return key;
    }
    public static byte[] generateIV() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16]; // AES block size is 128 bits (16 bytes)
        secureRandom.nextBytes(iv);
        return iv;
    }

    public static void main(String[] args) throws Exception {
        byte[] key = generateKey(256);
        byte[] iv = generateIV();
        String plaintext = "Hello, world!";
        byte[] encrypted = encrypt(plaintext.getBytes(StandardCharsets.UTF_8), key, iv);
        byte[] decrypted = decrypt(encrypted, key, iv);
        System.out.println(new String(decrypted, StandardCharsets.UTF_8)); // Output: Hello, world!
        //Using Base64 for strings
        String encryptedString = Base64.getEncoder().encodeToString(encrypted);
        byte[] decryptedFromString = Base64.getDecoder().decode(encryptedString);
        System.out.println(new String(decrypt(decryptedFromString, key, iv), StandardCharsets.UTF_8));

    }
}
