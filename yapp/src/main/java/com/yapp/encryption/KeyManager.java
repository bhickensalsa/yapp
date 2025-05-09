package com.yapp.encryption;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Manages RSA key generation, storage, and serialization.
 * <p>
 * Provides methods to generate key pairs, retrieve raw or Base64-encoded public keys,
 * and decode public keys from byte arrays or Base64 strings.
 * </p>
 *
 * Throws only {@link GeneralSecurityException} for all cryptographic operations,
 * simplifying exception handling in production code.
 * 
 * @author Philip Jonsson
 * @version 2025-05-09
 */
public class KeyManager {
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    /**
     * Constructs a KeyManager with a generated RSA key pair.
     *
     * @param keySize key size in bits (e.g., 2048)
     * @throws GeneralSecurityException if RSA key generation fails
     */
    public KeyManager(int keySize) throws GeneralSecurityException {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(keySize);
            KeyPair pair = keyGen.generateKeyPair();
            this.privateKey = pair.getPrivate();
            this.publicKey = pair.getPublic();
        } catch (NoSuchAlgorithmException | InvalidParameterException e) {
            throw new GeneralSecurityException("Failed to generate RSA key pair", e);
        }
    }

    /**
     * Returns this instance's public key.
     *
     * @return the public RSA key
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Returns this instance's private key.
     * Limited visibility to package-level for security.
     *
     * @return the private RSA key
     */
    PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Returns the raw byte encoding of a given public key.
     *
     * @param key the public key to encode
     * @return the encoded key as a byte array
     */
    public static byte[] encodePublicKey(PublicKey key) {
        return key.getEncoded();
    }

    /**
     * Returns the Base64-encoded string of a given public key.
     *
     * @param key the public key to encode
     * @return Base64 representation of the key
     */
    public static String encodePublicKeyToBase64(PublicKey key) {
        return Base64.getEncoder().encodeToString(encodePublicKey(key));
    }

    /**
     * Decodes a raw byte array into a public key.
     *
     * @param keyBytes encoded key bytes
     * @return the decoded public key
     * @throws GeneralSecurityException if decoding fails
     */
    public static PublicKey decodePublicKey(byte[] keyBytes) throws GeneralSecurityException {
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePublic(new X509EncodedKeySpec(keyBytes));
        } catch (Exception e) {
            throw new GeneralSecurityException("Failed to decode public key bytes", e);
        }
    }

    /**
     * Decodes a Base64 string into a public key.
     *
     * @param keyBase64 the Base64-encoded string
     * @return the decoded public key
     * @throws GeneralSecurityException if decoding fails
     */
    public static PublicKey decodePublicKey(String keyBase64) throws GeneralSecurityException {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
            return decodePublicKey(keyBytes);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("Invalid Base64 input", e);
        }
    }

    /**
     * Returns the public key encoded in Base64 (for logging or fallback support).
     *
     * @return the Base64 string of the public key
     */
    public String getPublicKeyAsBase64() {
        return encodePublicKeyToBase64(this.publicKey);
    }

    /**
     * Returns the raw byte array of the current public key.
     *
     * @return byte[] representation of public key
     */
    public byte[] getPublicKeyAsBytes() {
        return encodePublicKey(this.publicKey);
    }
}
