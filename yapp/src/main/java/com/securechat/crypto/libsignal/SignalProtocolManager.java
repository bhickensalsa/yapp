package com.securechat.crypto.libsignal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.protocol.*;
import org.whispersystems.libsignal.state.*;

import java.nio.charset.StandardCharsets;

/**
 * Handles session creation, encryption, and decryption using the Signal Protocol.
 */
public class SignalProtocolManager {

    private static final Logger logger = LoggerFactory.getLogger(SignalProtocolManager.class);

    private final SignalProtocolStore store;

    public SignalProtocolManager(SignalProtocolStore store) {
        this.store = store;
    }

    /**
     * Initializes a session with the recipient using their PreKeyBundle.
     */
    public void initializeSession(SignalProtocolAddress remoteAddress, PreKeyBundle preKeyBundle) {
        try {
            logger.debug("Initializing session with {}", remoteAddress);
            SessionBuilder sessionBuilder = new SessionBuilder(store, remoteAddress);
            sessionBuilder.process(preKeyBundle);
            logger.info("Session successfully initialized with {}", remoteAddress);
        } catch (InvalidKeyException | UntrustedIdentityException e) {
            logger.error("Failed to initialize session with {}: {}", remoteAddress, e.getMessage(), e);
        }
    }

    /**
     * Encrypts a plaintext message using an existing session.
     * Returns a SignalMessage that can be serialized and sent.
     */
    public SignalMessage encryptMessage(SignalProtocolAddress recipientAddress, String plaintext) {
        try {
            SessionCipher cipher = new SessionCipher(store, recipientAddress);
            CiphertextMessage ciphertextMessage = cipher.encrypt(plaintext.getBytes(StandardCharsets.UTF_8));
            // Construct SignalMessage from serialized bytes to ensure format
            SignalMessage signalMessage = new SignalMessage(ciphertextMessage.serialize());
            logger.info("SignalMessage successfully built for {}", recipientAddress);
            return signalMessage;
        } catch (UntrustedIdentityException e) {
            logger.error("Untrusted identity while encrypting message for {}: {}", recipientAddress, e.getMessage(), e);
            return null;
        } catch (Exception e) {
            logger.error("Encryption failed for {}: {}", recipientAddress, e.getMessage(), e);
            return null;
        }
    }

    /**
     * Decrypts a SignalMessage and returns the plaintext string.
     */
    public String decryptMessage(SignalProtocolAddress address, SignalMessage message) {
        try {
            logger.debug("Decrypting SignalMessage from {}", address);
            SessionCipher cipher = new SessionCipher(store, address);
            byte[] plaintext = cipher.decrypt(message);
            logger.info("Successfully decrypted SignalMessage from {}", address);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (Exception e) {
            logger.error("Failed to decrypt SignalMessage from {}: {}", address, e.getMessage(), e);
            return null;
        }
    }

    /**
     * Builds an initial PreKeySignalMessage using a PreKeyBundle.
     * Returns the PreKeySignalMessage to be serialized and sent.
     */
    public PreKeySignalMessage buildInitialPreKeyMessage(SignalProtocolAddress recipient, PreKeyBundle bundle, String plaintext) {
        try {
            logger.debug("Building initial PreKeySignalMessage for {} using PreKeyBundle", recipient);

            SessionBuilder sessionBuilder = new SessionBuilder(store, recipient);
            sessionBuilder.process(bundle);

            SessionCipher cipher = new SessionCipher(store, recipient);
            CiphertextMessage ciphertextMessage = cipher.encrypt(plaintext.getBytes(StandardCharsets.UTF_8));

            if (ciphertextMessage.getType() == CiphertextMessage.PREKEY_TYPE) {
                PreKeySignalMessage preKeySignalMessage = new PreKeySignalMessage(ciphertextMessage.serialize());
                logger.info("Initial PreKeySignalMessage successfully built for {}", recipient);
                return preKeySignalMessage;
            } else {
                logger.error("Expected a PreKeySignalMessage but received a regular SignalMessage.");
                return null;
            }
        } catch (Exception e) {
            logger.error("Failed to build initial PreKeySignalMessage for {}: {}", recipient, e.getMessage(), e);
            return null;
        }
    }

    /**
     * Decrypts a PreKeySignalMessage and returns the plaintext string.
     */
    public String decryptPreKeyMessage(SignalProtocolAddress address, PreKeySignalMessage message) {
        try {
            logger.debug("Decrypting PreKeySignalMessage from {}", address);
            SessionCipher cipher = new SessionCipher(store, address);
            byte[] plaintext = cipher.decrypt(message);
            logger.info("Successfully decrypted PreKeySignalMessage from {}", address);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (Exception e) {
            logger.error("Failed to decrypt PreKeySignalMessage from {}: {}", address, e.getMessage(), e);
            return null;
        }
    }

    /**
     * Checks if a session already exists with the given address.
     */
    public boolean hasSession(String userId, int deviceId) {
        return store.containsSession(new SignalProtocolAddress(userId, deviceId));
    }
}
