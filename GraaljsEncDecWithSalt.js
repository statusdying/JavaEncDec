// CryptoJSCompat.js

// Import the Java class (make sure CryptoJSCompat.class is in your classpath)
const CryptoJSCompat = Java.type('CryptoJSCompat');

// --- Encryption (data, password, salt, iv) ---
function encrypt(plaintext, password, salt, iv) {
    return CryptoJSCompat.encrypt(plaintext, password, salt, iv);
}

// --- Decryption (data, password, salt, iv) ---
function decrypt(ciphertext, password, salt, iv) {
    return CryptoJSCompat.decrypt(ciphertext, password, salt, iv);
}

// --- Salt and IV Generation (using Java methods) ---
function generateSalt() {
    return CryptoJSCompat.generateSalt();
}

function generateIV() {
    return CryptoJSCompat.generateIV();
}

function saltToBase64(salt){
    return CryptoJSCompat.saltToBase64(salt);
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
