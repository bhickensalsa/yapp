package com.yapp.encryption;

import java.security.PublicKey;

/**
 * Interface for message encryption and decryption.
 * 
 * This interface defines two methods for encrypting and decrypting messages, 
 * and a getter for the publicKey.
 * 
 * @author Philip Jonsson
 * @version 2025-05-09
 */
public interface Encryptor {

    /**
     * Encrypts the given message.
     */
    String encrypt(String message, PublicKey receiverPublicKey) throws Exception;

    /**
     * Decrypts the given message.
     */
    String decrypt(String encryptedMessage) throws Exception;

    /**
     * @return the public key of the encryptor.
     */
    PublicKey getPublicKey();
}