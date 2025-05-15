package com.securechat.crypto;

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
    String encrypt(String plainText, byte[] publicKey) throws Exception;

    /**
     * Decrypts the given message.
     */
    String decrypt(String cipherText, byte[] privateKey) throws Exception;

    /**
     * @return the public key of the encryptor.
     */
    /* PublicKey getPublicKey(); */
}