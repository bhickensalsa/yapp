package com.yapp.encryption;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

/**
 * Handles encryption and decryption using RSA via {@link RSAEncryptor} and key management via {@link KeyManager}.
 * <p>
 * Implements {@link Encryptor} interface for public encryption API. Uses RSA with OAEP and SHA-256 padding.
 * </p>
 * <p>
 * Encapsulates private key access to minimize surface area for potential misuse.
 * </p>
 * 
 * @author Philip Jonsson
 * @version 2025-05-09
 */
public class EncryptionManager implements Encryptor {
    private static final int DEFAULT_KEY_SIZE = 2048;

    private final KeyManager keyManager;
    private final RSAEncryptor encryptor;

    /**
     * Constructs an EncryptionManager with default RSA key size.
     *
     * @throws GeneralSecurityException if key generation or cipher setup fails
     */
    public EncryptionManager() throws GeneralSecurityException {
        this(DEFAULT_KEY_SIZE);
    }

    /**
     * Constructs an EncryptionManager with a specified RSA key size.
     *
     * @param keySize the RSA key size in bits (e.g. 2048, 3072)
     * @throws GeneralSecurityException if key generation fails
     */
    public EncryptionManager(int keySize) throws GeneralSecurityException {
        this.keyManager = new KeyManager(keySize);
        this.encryptor = new RSAEncryptor();
    }

    /**
     * Returns the public key object for use in encryption.
     *
     * @return the public RSA key
     */
    @Override
    public PublicKey getPublicKey() {
        return keyManager.getPublicKey();
    }

    /**
     * Returns the public key encoded as a raw byte array, for transmission over sockets.
     *
     * @return byte array of public key
     */
    public byte[] getPublicKeyAsBytes() {
        return keyManager.getPublicKeyAsBytes();
    }

    /**
     * Encrypts a plaintext message with the recipient's public key.
     *
     * @param message       the plaintext message
     * @param recipientKey  the recipient's public RSA key
     * @return Base64-encoded ciphertext
     * @throws GeneralSecurityException if encryption fails
     */
    @Override
    public String encrypt(String message, PublicKey recipientKey) throws GeneralSecurityException {
        return encryptor.encrypt(message, recipientKey);
    }

    /**
     * Decrypts an incoming Base64-encoded message using the local private key.
     *
     * @param message the Base64-encoded encrypted message
     * @return the decrypted plaintext
     * @throws GeneralSecurityException if decryption fails
     */
    @Override
    public String decrypt(String message) throws GeneralSecurityException {
        return encryptor.decrypt(message, keyManager.getPrivateKey());
    }
}
