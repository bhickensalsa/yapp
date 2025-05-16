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
     * Attempts to decrypt any incoming ciphertext by detecting message type (PreKey or Signal).
     */
    public String decryptAny(SignalProtocolAddress sender, byte[] ciphertext) {
        SessionCipher cipher = new SessionCipher(store, sender);
        try {
            logger.debug("Attempting to decrypt message from {} as PreKeySignalMessage", sender);
            PreKeySignalMessage preKeyMessage = new PreKeySignalMessage(ciphertext);
            byte[] plaintext = cipher.decrypt(preKeyMessage);
            logger.info("Successfully decrypted PreKeySignalMessage from {}", sender);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (InvalidMessageException e) {
            logger.debug("Not a PreKeySignalMessage from {}: {}", sender, e.getMessage());
            // Fall through to attempt SignalMessage
        } catch (Exception e) {
            logger.error("Error while decrypting PreKeySignalMessage from {}: {}", sender, e.getMessage(), e);
            return null;
        }

        try {
            logger.debug("Attempting to decrypt message from {} as SignalMessage", sender);
            SignalMessage signalMessage = new SignalMessage(ciphertext);
            byte[] plaintext = cipher.decrypt(signalMessage);
            logger.info("Successfully decrypted SignalMessage from {}", sender);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (Exception e) {
            logger.error("Failed to decrypt SignalMessage from {}: {}", sender, e.getMessage(), e);
            return null;
        }
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
     * Encrypts a message using an existing session.
     */
    public EncryptedMessageResult encryptMessage(SignalProtocolAddress address, String plaintext) {
        try {
            SessionCipher cipher = new SessionCipher(store, address);
            CiphertextMessage message = cipher.encrypt(plaintext.getBytes(StandardCharsets.UTF_8));

            boolean isPreKeyMessage = message.getType() == CiphertextMessage.PREKEY_TYPE;
            logger.info("Message encrypted for {} (isPreKeyMessage={})", address, isPreKeyMessage);
            return new EncryptedMessageResult(message.serialize(), isPreKeyMessage);
        } catch (UntrustedIdentityException e) {
            logger.error("Untrusted identity while encrypting message for {}: {}", address, e.getMessage(), e);
            return null;
        } catch (Exception e) {
            logger.error("Encryption failed for {}: {}", address, e.getMessage(), e);
            return null;
        }
    }

    /**
     * Encrypts an initial message using a PreKeyBundle, establishing a session in the process.
     */
    public EncryptedMessageResult encryptPreKeyMessage(SignalProtocolAddress recipient, PreKeyBundle bundle, String plaintext) {
        try {
            logger.debug("Encrypting initial message to {} using PreKeyBundle", recipient);
            SessionBuilder sessionBuilder = new SessionBuilder(store, recipient);
            sessionBuilder.process(bundle);

            SessionCipher cipher = new SessionCipher(store, recipient);
            CiphertextMessage message = cipher.encrypt(plaintext.getBytes(StandardCharsets.UTF_8));

            boolean isPreKeyMessage = message.getType() == CiphertextMessage.PREKEY_TYPE;
            logger.info("Initial message encrypted for {} (isPreKeyMessage={})", recipient, isPreKeyMessage);
            return new EncryptedMessageResult(message.serialize(), isPreKeyMessage);
        } catch (Exception e) {
            logger.error("Failed to encrypt initial message to {}: {}", recipient, e.getMessage(), e);
            return null;
        }
    }

    /**
     * Decrypts a PreKeySignalMessage and automatically establishes a session.
     */
    public String decryptPreKeyMessage(SignalProtocolAddress address, byte[] ciphertext) {
        try {
            logger.debug("Decrypting PreKeySignalMessage from {}", address);
            SessionCipher cipher = new SessionCipher(store, address);
            PreKeySignalMessage message = new PreKeySignalMessage(ciphertext);
            byte[] plaintext = cipher.decrypt(message);
            logger.info("Successfully decrypted PreKeySignalMessage from {}", address);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (Exception e) {
            logger.error("Failed to decrypt PreKeySignalMessage from {}: {}", address, e.getMessage(), e);
            return null;
        }
    }

    /**
     * Decrypts a regular SignalMessage.
     */
    public String decryptMessage(SignalProtocolAddress address, byte[] ciphertext) {
        try {
            logger.debug("Decrypting SignalMessage from {}", address);
            SessionCipher cipher = new SessionCipher(store, address);
            SignalMessage message = new SignalMessage(ciphertext);
            byte[] plaintext = cipher.decrypt(message);
            logger.info("Successfully decrypted SignalMessage from {}", address);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (Exception e) {
            logger.error("Failed to decrypt SignalMessage from {}: {}", address, e.getMessage(), e);
            return null;
        }
    }

    /**
     * Checks if a session already exists with the given address.
     */
    public boolean hasSession(String userId) {
        try {
            boolean exists = store.containsSession(new SignalProtocolAddress(userId, 1)); // deviceId should be passed in correctly
            logger.debug("Session check for {} returned {}", userId, exists);
            return exists;
        } catch (Exception e) {
            logger.error("Error while checking session for {}: {}", userId, e.getMessage(), e);
            return false;
        }
    }
}
