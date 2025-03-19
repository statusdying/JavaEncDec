// Import the necessary Java classes.
const Cipher = Java.type('javax.crypto.Cipher');
const SecretKeySpec = Java.type('javax.crypto.spec.SecretKeySpec');
const IvParameterSpec = Java.type('javax.crypto.spec.IvParameterSpec');
const SecureRandom = Java.type('java.security.SecureRandom');
const StandardCharsets = Java.type('java.nio.charset.StandardCharsets');
const Base64 = Java.type('java.util.Base64');
const PBEKeySpec = Java.type('javax.crypto.spec.PBEKeySpec');
const SecretKeyFactory = Java.type('javax.crypto.SecretKeyFactory');

const ALGORITHM = "AES";
const TRANSFORMATION = "AES/CBC/PKCS5Padding";
const PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256"; // More secure than SHA1
const ITERATION_COUNT = 65536; // Higher iteration count is more secure
const KEY_LENGTH = 256; // 256-bit AES

// --- Key and IV Generation (with Salt) ---

function generateSalt() {
    const secureRandom = new SecureRandom();
    const salt = new (Java.type('byte[]'))(16); // 16 bytes (128 bits) is a good salt size
    secureRandom.nextBytes(salt);
    return salt;
}

function generateKey(password, salt) {
    try {
        const factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        // Correctly create a Java char[] from the JavaScript string
        const passwordCharArray = new (Java.type('char[]'))(password.length);
        for (let i = 0; i < password.length; i++) {
            passwordCharArray[i] = password.charCodeAt(i);
        }

        const spec = new PBEKeySpec(passwordCharArray, salt, ITERATION_COUNT, KEY_LENGTH);
        const tmp = factory.generateSecret(spec);
        const secretKey = new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
        return secretKey.getEncoded(); // Return the key as a byte array
    } catch (e) {
        throw e;
    }
}

function generateIV() {
    const secureRandom = new SecureRandom();
    const iv = new (Java.type('byte[]'))(16); // AES block size is 128 bits (16 bytes)
    secureRandom.nextBytes(iv);
    return iv;
}

// --- Encryption ---

function encrypt(plaintext, key, iv) {
    try {
        const secretKeySpec = new SecretKeySpec(key, ALGORITHM);
        const ivParameterSpec = new IvParameterSpec(iv);
        const cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(plaintext);
    } catch (e) {
        throw e;
    }
}

// --- String Encryption ---
function encryptString(plaintext, password, salt, iv) {
    const key = generateKey(password, salt); // Generate key from password and salt
    const encryptedBytes = encrypt(Java.to(plaintext.getBytes(StandardCharsets.UTF_8), "byte[]"), key, iv);
    return Base64.getEncoder().encodeToString(encryptedBytes);
}

// --- Decryption ---

function decrypt(ciphertext, key, iv) {
    try {
        const secretKeySpec = new SecretKeySpec(key, ALGORITHM);
        const ivParameterSpec = new IvParameterSpec(iv);
        const cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(ciphertext);
    } catch (e) {
        throw e;
    }
}

// --- String Decryption ---
function decryptString(base64Ciphertext, password, salt, iv) {
    const key = generateKey(password, salt); // Generate key from password and salt
    const cipherText = Base64.getDecoder().decode(base64Ciphertext);
    const plainTextBytes = decrypt(cipherText, key, iv);
    return new (Java.type('java.lang.String'))(plainTextBytes, StandardCharsets.UTF_8);
}

// --- Main (Example Usage) ---

function main() {
    const password = "myStrongPassword"; // Use a strong password
    const salt = generateSalt();
    const iv = generateIV();
    const plaintext = "This is a secret message!";

    // Encrypt and decrypt using strings
    const encrypted = encryptString(plaintext, password, salt, iv);
    console.log("Encrypted (Base64):", encrypted);
    const decrypted = decryptString(encrypted, password, salt, iv);
    console.log("Decrypted (Base64):", decrypted);

    // Example showing how to convert salt and iv to Base64 for storage
    const base64Salt = Base64.getEncoder().encodeToString(salt);
    const base64Iv = Base64.getEncoder().encodeToString(iv);
    console.log("Base64 Salt:", base64Salt);
    console.log("Base64 IV:", base64Iv);

    //Example showing how to convert Base64 encoded salt and iv back to byte arrays
    const decodedSalt = Base64.getDecoder().decode(base64Salt);
    const decodedIv = Base64.getDecoder().decode(base64Iv);

    //Encrypt and decrypt with converted values.
    const encrypted2 = encryptString(plaintext, password, decodedSalt, decodedIv);
    console.log("Encrypted (Base64) with decoded Salt/IV:", encrypted2);
    const decrypted2 = decryptString(encrypted2, password, decodedSalt, decodedIv);
    console.log("Decrypted (Base64) with decoded Salt/IV:", decrypted2);

    //Demonstrate different salt creates different ciphertext.
    const salt2 = generateSalt();
    const iv2 = generateIV();
    const encrypted3 = encryptString(plaintext, password, salt2, iv2);
    console.log("Encrypted (Base64) with different Salt/IV:", encrypted3); // This will be different.
    // Decrypting 'encrypted3' with 'salt' and 'iv' will result in an error.

    // Show how different passwords result in different keys and thus different ciphertexts.
     const encrypted4 = encryptString(plaintext, "anotherPassword", salt, iv);
     console.log("Encrypted (Base64) with another password:", encrypted4);  // Different from 'encrypted'.
}
main();
