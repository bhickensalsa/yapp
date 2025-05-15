package com.securechat.crypto.libsignal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.state.*;
import org.whispersystems.libsignal.protocol.*;

public class SignalProtocolManager {

    private static final Logger logger = LoggerFactory.getLogger(SignalProtocolManager.class);

    private final SignalProtocolStore store;

    public SignalProtocolManager(SignalProtocolStore store) {
        this.store = store;
    }

    // Initializes a session with a remote user by processing their prekey bundle.
    public void initializeSession(SignalProtocolAddress remoteAddress, PreKeyBundle preKeyBundle) {
        try {
            logger.debug("Initializing session with remote address: {}", remoteAddress);
            SessionBuilder sessionBuilder = new SessionBuilder(store, remoteAddress);
            sessionBuilder.process(preKeyBundle);
            logger.info("Session initialized with {}", remoteAddress);
        } catch (InvalidKeyException | UntrustedIdentityException e) {
            logger.error("Failed to initialize session with {}: {}", remoteAddress, e.getMessage(), e);
        }
    }

    // Encrypts a plaintext message for the given recipient.
    public byte[] encryptMessage(SignalProtocolAddress recipient, String plaintext) {
        try {
            if (!store.containsSession(recipient)) {
                logger.warn("No session found for {}, cannot encrypt message", recipient);
                return null;
            }
            logger.debug("Encrypting message for recipient {}", recipient);
            SessionCipher cipher = new SessionCipher(store, recipient);
            byte[] ciphertext = cipher.encrypt(plaintext.getBytes()).serialize();
            logger.info("Message encrypted for recipient {}", recipient);
            return ciphertext;
        } catch (UntrustedIdentityException e) {
            logger.error("Failed to encrypt message for {}: {}", recipient, e.getMessage(), e);
            return null;
        } catch (IllegalArgumentException e) {
            logger.error("Unexpected error encrypting message for {}: {}", recipient, e.getMessage(), e);
            return null;
        }
    }

    // Decrypts an encrypted message from the sender.
    public String decryptMessage(SignalProtocolAddress sender, byte[] encryptedMessageBytes) {
        try {
            logger.debug("Decrypting message from sender {}", sender);
            SessionCipher cipher = new SessionCipher(store, sender);
            SignalMessage encryptedMessage = new SignalMessage(encryptedMessageBytes);
            byte[] decryptedBytes = cipher.decrypt(encryptedMessage);
            String plaintext = new String(decryptedBytes);
            logger.info("Message decrypted from sender {}", sender);
            return plaintext;
        } catch (InvalidMessageException | LegacyMessageException | DuplicateMessageException |
                 NoSessionException | UntrustedIdentityException e) {
            logger.error("Failed to decrypt message from {}: {}", sender, e.getMessage(), e);
            return null;
        }
    }

    // Encrypts a plaintext message for an unestablished session using a PreKeySignalMessage.
    public byte[] encryptPreKeyMessage(SignalProtocolAddress recipient, String plaintext) {
        try {
            logger.debug("Encrypting pre-key message for recipient {}", recipient);
            SessionCipher cipher = new SessionCipher(store, recipient);
            byte[] ciphertext = cipher.encrypt(plaintext.getBytes()).serialize();
            logger.info("Pre-key message encrypted for recipient {}", recipient);
            return ciphertext;
        } catch (UntrustedIdentityException e) {
            logger.error("Failed to encrypt pre-key message for {}: {}", recipient, e.getMessage(), e);
            return null;
        }
    }

    // Decrypts a PreKeySignalMessage from the sender and establishes a session.
    public String decryptPreKeyMessage(SignalProtocolAddress sender, byte[] preKeyMessageBytes) {
        try {
            logger.debug("Decrypting pre-key message from sender {}", sender);
            PreKeySignalMessage preKeySignalMessage = new PreKeySignalMessage(preKeyMessageBytes);
            SessionCipher cipher = new SessionCipher(store, sender);
            byte[] decryptedBytes = cipher.decrypt(preKeySignalMessage);
            String plaintext = new String(decryptedBytes);
            logger.info("Pre-key message decrypted from sender {}", sender);
            return plaintext;
        } catch (UntrustedIdentityException | InvalidMessageException | InvalidVersionException |
                 DuplicateMessageException | LegacyMessageException | InvalidKeyIdException | InvalidKeyException e) {
            logger.error("Failed to decrypt pre-key message from {}: {}", sender, e.getMessage(), e);
            return null;
        }
    }
}
