package com.yapp.encryption;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

/**
 * Provides RSA-based encryption and decryption using OAEP with SHA-256 padding.
 * <p>
 * Designed for secure asymmetric encryption of small payloads, such as session keys or short messages.
 * This implementation uses the "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" cipher transformation.
 * </p>
 * 
 * @author Philip Jonsson
 * @version 2025-05-09
 */
public class RSAEncryptor {

    private static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    /**
     * Encrypts a UTF-8 plaintext string using the recipient's public RSA key.
     *
     * @param message the plaintext message to encrypt
     * @param key     the recipient's public RSA key
     * @return a Base64-encoded encrypted message
     * @throws GeneralSecurityException if encryption fails
     */
    public String encrypt(String message, PublicKey key) throws GeneralSecurityException {
        try {
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] ciphertext = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new GeneralSecurityException("RSA encryption failed", e);
        }
    }

    /**
     * Decrypts a Base64-encoded message using the local private RSA key.
     *
     * @param encrypted the Base64-encoded encrypted message
     * @param key       the private RSA key
     * @return the original UTF-8 plaintext
     * @throws GeneralSecurityException if decryption fails
     */
    public String decrypt(String encrypted, PrivateKey key) throws GeneralSecurityException {
        try {
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] plaintextBytes = cipher.doFinal(Base64.getDecoder().decode(encrypted));
            return new String(plaintextBytes, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new GeneralSecurityException("RSA decryption failed", e);
        }
    }
}

// TODO: RSA is not suitable for large plaintext data. Hybrid encryption (e.g., AES+RSA) is recommended for production systems.