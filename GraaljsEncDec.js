// Import the necessary Java classes.  This is the key to interoperability!
const Cipher = Java.type('javax.crypto.Cipher');
const SecretKeySpec = Java.type('javax.crypto.spec.SecretKeySpec');
const IvParameterSpec = Java.type('javax.crypto.spec.IvParameterSpec');
const SecureRandom = Java.type('java.security.SecureRandom');
const StandardCharsets = Java.type('java.nio.charset.StandardCharsets');
const Base64 = Java.type('java.util.Base64');

const ALGORITHM = "AES";
const TRANSFORMATION = "AES/CBC/PKCS5Padding";

// --- Key and IV Generation ---

function generateKey(keySizeBits) {
    const secureRandom = new SecureRandom();
    const key = new (Java.type('byte[]'))(keySizeBits / 8);
    secureRandom.nextBytes(key);
    return key;
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
        // Handle exceptions appropriately (e.g., log, re-throw, etc.)
        throw e; // Re-throwing for this example
    }
}
// --- String Encryption ---
function encryptString(plaintext, key, iv){
    const encryptedBytes = encrypt(Java.to(plaintext.getBytes(StandardCharsets.UTF_8),"byte[]"), key, iv); //string to java byte array
    return Base64.getEncoder().encodeToString(encryptedBytes); // Return as Base64 string

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
        // Handle exceptions appropriately
        throw e;
    }
}
// --- String Decryption ---
function decryptString(base64Ciphertext, key, iv){
    const cipherText = Base64.getDecoder().decode(base64Ciphertext);
    const plainTextBytes = decrypt(cipherText,key, iv);
    return new (Java.type('java.lang.String'))(plainTextBytes, StandardCharsets.UTF_8) //to java string
}

// --- Main (Example Usage) ---

function main() {
    const key = generateKey(256);
    const iv = generateIV();
    const plaintext = "This is a secret message!";

    // Encrypt and decrypt using byte arrays
    const encryptedBytes = encrypt(Java.to(plaintext.getBytes(StandardCharsets.UTF_8),"byte[]"), key, iv); //string to java byte array
    const decryptedBytes = decrypt(encryptedBytes, key, iv);
    const decryptedText = new (Java.type('java.lang.String'))(decryptedBytes, StandardCharsets.UTF_8); //byte array to java String
    console.log("Decrypted (byte array):", decryptedText);

    //Encrypt and decrypt using strings.
    const encrypted = encryptString(plaintext, key, iv);
    console.log("Encrypted (Base64):", encrypted);
     const decrypted = decryptString(encrypted, key, iv);
    console.log("Decrypted (Base64):", decrypted);
}

main();
