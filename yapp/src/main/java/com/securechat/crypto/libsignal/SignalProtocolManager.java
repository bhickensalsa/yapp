package com.securechat.crypto.libsignal;

import java.nio.charset.StandardCharsets;

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
    public EncryptedMessageResult encryptMessage(SignalProtocolAddress address, String plaintext) {
        SessionCipher cipher = new SessionCipher(store, address);

        try {
            CiphertextMessage message = cipher.encrypt(plaintext.getBytes(StandardCharsets.UTF_8));
            return new EncryptedMessageResult(message.serialize(), false);
        } catch (UntrustedIdentityException e) {
            logger.error("Untrusted identity while encrypting message for {}: {}", address, e.getMessage(), e);
            return null; // or rethrow as a custom exception if needed
        }
    }

    // Decrypts an encrypted message from the sender.
    public String decryptMessage(SignalProtocolAddress address, byte[] ciphertext) {
    try {
        SessionCipher cipher = new SessionCipher(store, address);
        SignalMessage signalMessage = new SignalMessage(ciphertext);
        byte[] plaintext = cipher.decrypt(signalMessage);
        return new String(plaintext, StandardCharsets.UTF_8);
    } catch (Exception e) {
        logger.error("Failed to decrypt SignalMessage: {}", e.getMessage(), e);
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
    public String decryptPreKeyMessage(SignalProtocolAddress address, byte[] ciphertext) {
        try {
            SessionCipher cipher = new SessionCipher(store, address);
            PreKeySignalMessage preKeyMessage = new PreKeySignalMessage(ciphertext);
            byte[] plaintext = cipher.decrypt(preKeyMessage);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (Exception e) {
            logger.error("Failed to decrypt PreKeySignalMessage: {}", e.getMessage(), e);
            return null;
        }
    }
}
