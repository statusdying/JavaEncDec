// aes-graaljs-direct-corrected.js

const Cipher = Java.type('javax.crypto.Cipher');
const SecretKeySpec = Java.type('javax.crypto.spec.SecretKeySpec');
const IvParameterSpec = Java.type('javax.crypto.spec.IvParameterSpec');
const SecureRandom = Java.type('java.security.SecureRandom');
const MessageDigest = Java.type('java.security.MessageDigest');
const StandardCharsets = Java.type('java.nio.charset.StandardCharsets');
const Base64 = Java.type('java.util.Base64');

const ALGORITHM = "AES";
const TRANSFORMATION = "AES/CBC/PKCS5Padding";
const KEY_SIZE_BITS = 128;
const IV_SIZE_BITS = 128;
const ITERATIONS = 1;

// --- Key and IV Derivation (CryptoJS-compatible) ---

function deriveKeyAndIV(password, salt, keySizeBits, ivSizeBits, iterations) {
    const passwordBytes = new (Java.type('java.lang.String'))(password).getBytes(StandardCharsets.UTF_8);
    let keyAndIv = new (Java.type('byte[]'))((keySizeBits / 8) + (ivSizeBits / 8));
    let currentHash = new (Java.type('byte[]'))(0);

    const md5 = MessageDigest.getInstance("MD5");

    for (let i = 0; i < iterations; i++) {
        let dataToHash;

        // Correctly combine password, salt, and previous hash.
        if (i === 0) {
            if (!salt || salt.length === 0) {
                dataToHash = passwordBytes;
            } else {
                dataToHash = new (Java.type('byte[]'))(passwordBytes.length + salt.length);
                Java.to(passwordBytes, dataToHash, 0, 0, passwordBytes.length);
                Java.to(salt, dataToHash, passwordBytes.length, 0, salt.length);
            }
        } else {
            if (!salt || salt.length === 0) {
                dataToHash = new (Java.type('byte[]'))(currentHash.length + passwordBytes.length);
                Java.to(currentHash, dataToHash, 0, 0, currentHash.length);
                Java.to(passwordBytes, dataToHash, currentHash.length, 0, passwordBytes.length);

            } else {
                dataToHash = new (Java.type('byte[]'))(currentHash.length + passwordBytes.length + salt.length);
                Java.to(currentHash, dataToHash, 0, 0, currentHash.length);
                Java.to(passwordBytes, dataToHash, currentHash.length, 0, passwordBytes.length);
                Java.to(salt, dataToHash, currentHash.length + passwordBytes.length, 0, salt.length);
            }
        }

        currentHash = md5.digest(dataToHash);
        let bytesNeeded = keyAndIv.length - (i * 16);
        if (bytesNeeded > 0) {
             // Correctly copy *only* the needed bytes.
            Java.to(currentHash, keyAndIv, i * 16, 0, Math.min(bytesNeeded, currentHash.length));
        }
    }

    // Split into key and IV
    const key = new (Java.type('byte[]'))(keySizeBits / 8);
    const iv = new (Java.type('byte[]'))(ivSizeBits / 8);
    Java.to(keyAndIv, key, 0, 0, key.length);
    Java.to(keyAndIv, iv, 0, key.length, iv.length);

    return { key: key, iv: iv };
}


// --- Encryption ---

function encrypt(plaintext, password, salt, iv) {
    try {
        let usedSalt = (salt === null || salt.length === 0) ? generateSalt() : salt;
        let keyAndIv;

        if (password !== null && password !== "") {
            keyAndIv = deriveKeyAndIV(password, usedSalt, KEY_SIZE_BITS, IV_SIZE_BITS, ITERATIONS);
        } else {
            if (iv === null || iv.length === 0) {
                throw new Error("IV must be provided if no password is used.");
            }
             keyAndIv = { key: generateKey(KEY_SIZE_BITS), iv: iv };
        }

        const secretKeySpec = new SecretKeySpec(keyAndIv.key, ALGORITHM);
        const ivParameterSpec = new IvParameterSpec(keyAndIv.iv);
        const cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        const encryptedBytes = cipher.doFinal(Java.to(new (Java.type('java.lang.String'))(plaintext).getBytes(StandardCharsets.UTF_8), 'byte[]'));
        let ciphertext = Base64.getEncoder().encodeToString(encryptedBytes);

        if ((password !== null && password !== "") && (salt === null || salt.length === 0)) {
            return "Salted__" + Base64.getEncoder().encodeToString(usedSalt) + ciphertext;
        } else {
            return ciphertext;
        }

    } catch (e) {
        console.error("Encryption error:", e);
        throw e;
    }
}

// --- Decryption ---

function decrypt(ciphertext, password, salt, iv) {
    try {
        let usedSalt = salt;
        let keyAndIV;

        if (password !== null && password !== "" && (salt === null || salt.length === 0)) {
            if (!ciphertext.startsWith("Salted__")) {
                throw new Error("Ciphertext is missing 'Salted__' prefix when password is used and no salt is provided.");
            }

            const saltAndCiphertext = ciphertext.substring(8);
            const decoded = Base64.getDecoder().decode(saltAndCiphertext);
            usedSalt = new (Java.type('byte[]'))(8);
            Java.to(decoded, usedSalt, 0, 0, 8);

            const actualCiphertextBytes = new (Java.type('byte[]'))(decoded.length - 8);
            Java.to(decoded, actualCiphertextBytes, 0, 8, actualCiphertextBytes.length);
            ciphertext = Base64.getEncoder().encodeToString(actualCiphertextBytes);
        }

        if(password !== null && password !== ""){
            keyAndIV = deriveKeyAndIV(password, usedSalt, KEY_SIZE_BITS, IV_SIZE_BITS, ITERATIONS);
        }else{
            if(iv === null || iv.length === 0){
                throw new Error("IV must be provided if no password is used.");
            }
            keyAndIV = {key: generateKey(KEY_SIZE_BITS), iv:iv};
        }

        const secretKeySpec = new SecretKeySpec(keyAndIV.key, ALGORITHM);
        const ivParameterSpec = new IvParameterSpec(keyAndIV.iv);
        const cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        const ciphertextBytes = Base64.getDecoder().decode(ciphertext);
        const decryptedBytes = cipher.doFinal(ciphertextBytes);
        return new (Java.type('java.lang.String'))(decryptedBytes, StandardCharsets.UTF_8);

    } catch (e) {
        console.error("Decryption error:", e);
        throw e;
    }
}

// --- Salt Generation ---

function generateSalt() {
    const secureRandom = new SecureRandom();
    const salt = new (Java.type('byte[]'))(8);
    secureRandom.nextBytes(salt);
    return salt;
}

// --- IV Generation ---

function generateIV() {
    const secureRandom = new SecureRandom();
    const iv = new (Java.type('byte[]'))(16);
    secureRandom.nextBytes(iv);
    return iv;
}

// --- Key Generation ---

function generateKey(keySizeBits) {
    const secureRandom = new SecureRandom();
    const key = new (Java.type('byte[]'))(keySizeBits / 8);
    secureRandom.nextBytes(key);
    return key;
}
// --- Utility function to convert byte array to Base64 string ---
function toBase64(byteArray) {
    return Base64.getEncoder().encodeToString(byteArray);
}

// --- Main (Example Usage) ---

function main() {
    const plaintext = "My secret message!";
    const password = "MyPassword";

    // --- Test with password and auto-generated salt/IV ---
    const encryptedWithPassword = encrypt(plaintext, password, null, null);
    console.log("Encrypted (with password, auto salt/IV):", encryptedWithPassword);
    const decryptedWithPassword = decrypt(encryptedWithPassword, password, null, null);
    console.log("Decrypted (with password, auto salt/IV):", decryptedWithPassword);

    // --- Test with password and provided salt/derived IV ---
    const salt = generateSalt();
    const encryptedWithPasswordAndSalt = encrypt(plaintext, password, salt, null);
    console.log("Encrypted (with password, provided salt, auto IV):", encryptedWithPasswordAndSalt);
    const decryptedWithPasswordAndSalt = decrypt(encryptedWithPasswordAndSalt, password, salt, null);
    console.log("Decrypted (with password, provided salt, auto IV):", decryptedWithPasswordAndSalt);

    // --- Test with password, salt, and IV ---
    const iv = generateIV();
    const encryptedWithPasswordSaltIV = encrypt(plaintext, password, salt, iv);
    console.log("Encrypted (with password, salt, and IV):", encryptedWithPasswordSaltIV);
    const decryptedWithPasswordSaltIV = decrypt(encryptedWithPasswordSaltIV, password, salt, iv);
    console.log("Decrypted (with password, salt, and IV):", decryptedWithPasswordSaltIV);

    // --- Test with no password, provided IV, random key---
    const encryptedWithIV = encrypt(plaintext, null, null, iv); // No password, auto key
    console.log("Encrypted (with IV, no password, auto key):", encryptedWithIV);
    const decryptedWithIV = decrypt(encryptedWithIV, null, null, iv);
    console.log("Decrypted (with IV, no password, auto key):", decryptedWithIV);

    // --- Additional tests, showing byte[] and String conversions ---
    console.log("\n--- Additional Tests ---");

	// Test using a byte array for the salt
	const saltBytes = generateSalt();
    const encryptedWithByteArraySalt = encrypt(plaintext, password, saltBytes, null);
    console.log("Encrypted (byte[] salt):", encryptedWithByteArraySalt);
    const decryptedWithByteArraySalt = decrypt(encryptedWithByteArraySalt, password, saltBytes, null);
    console.log("Decrypted (byte[] salt):", decryptedWithByteArraySalt);

	// Test using byte array for the IV
	const ivBytes = generateIV();
    const encryptedWithByteArrayIV = encrypt(plaintext, null, null, ivBytes);
    console.log("Encrypted (byte[] IV):", encryptedWithByteArrayIV);
	const decryptedWithByteArrayIV = decrypt(encryptedWithByteArrayIV, null, null, ivBytes);
    console.log("Decrypted (byte[] IV):", decryptedWithByteArrayIV);
}

main();
