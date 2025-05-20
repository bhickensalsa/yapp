package com.securechat.crypto.libsignal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;

public class SignalProtocolManager {

    private static final Logger logger = LoggerFactory.getLogger(SignalProtocolManager.class);
    private static final String LOG_PREFIX = "[SignalProtocolManager]";

    private final SignalProtocolStore store;

    public SignalProtocolManager(SignalProtocolStore store) {
        this.store = store;
        logger.debug("{} Created with provided SignalProtocolStore", LOG_PREFIX);
    }


    public SignalProtocolStore getStore() {
        return store;
    }


    public void initializeSession(String peerId, PreKeyBundle bundle) throws InvalidKeyException {
        SignalProtocolAddress address = new SignalProtocolAddress(peerId, bundle.getDeviceId());
        SessionBuilder builder = new SessionBuilder(store, address);
        try {
            builder.process(bundle);
            // Save updated session explicitly
            SessionRecord updatedSession = store.loadSession(address);
            store.storeSession(address, updatedSession);
            logger.info("{} Initialized and saved session with peer {} device {}", LOG_PREFIX, peerId, bundle.getDeviceId());
        } catch (Exception e) {
            logger.error("{} Failed to process PreKeyBundle for peer {} device {}: {}", LOG_PREFIX, peerId, bundle.getDeviceId(), e.getMessage(), e);
            throw new InvalidKeyException("Failed to process PreKeyBundle", e);
        }
    }

    public boolean hasSession(String peerId, int deviceId) {
        SignalProtocolAddress address = new SignalProtocolAddress(peerId, deviceId);
        try {
            SessionRecord record = store.loadSession(address);
            boolean exists = record != null && record.getSessionState().getSessionVersion() > 0;
            logger.debug("{} Session check for peer {} device {}: {}", LOG_PREFIX, peerId, deviceId, exists);
            return exists;
        } catch (Exception e) {
            logger.warn("{} Error checking session for peer {} device {}: {}", LOG_PREFIX, peerId, deviceId, e.getMessage(), e);
            return false;
        }
    }

    public byte[] encryptMessage(String peerId, int deviceId, String plaintext) throws Exception {
        if (!hasSession(peerId, deviceId)) {
            String errMsg = LOG_PREFIX + " No session exists with " + peerId + ":" + deviceId + " for message encryption.";
            logger.error(errMsg);
            throw new IllegalStateException(errMsg);
        }

        SignalProtocolAddress address = new SignalProtocolAddress(peerId, deviceId);
        SessionCipher cipher = new SessionCipher(store, address);
        CiphertextMessage message = cipher.encrypt(plaintext.getBytes(StandardCharsets.UTF_8));

        // Explicitly save updated session after encryption
        SessionRecord updatedSession = store.loadSession(address);
        store.storeSession(address, updatedSession);

        logger.info("{} Encrypted message for peer {} device {}", LOG_PREFIX, peerId, deviceId);
        return message.serialize();
    }

    public byte[] encryptPreKeyMessage(String peerId, int deviceId, String plaintext) throws Exception {
        SignalProtocolAddress address = new SignalProtocolAddress(peerId, deviceId);
        SessionCipher cipher = new SessionCipher(store, address);
        CiphertextMessage message = cipher.encrypt(plaintext.getBytes(StandardCharsets.UTF_8));

        // Explicitly save updated session after encryption
        SessionRecord updatedSession = store.loadSession(address);
        store.storeSession(address, updatedSession);

        logger.info("{} Encrypted PreKey message for peer {} device {}", LOG_PREFIX, peerId, deviceId);
        return message.serialize();
    }

    public String decryptPreKeyMessage(String senderId, int senderDeviceId, byte[] ciphertext) throws Exception {
        if (!hasSession(senderId, senderDeviceId)) {
            String errMsg = LOG_PREFIX + " No session found with " + senderId + ":" + senderDeviceId + " for PreKey decryption.";
            logger.error(errMsg);
            throw new IllegalStateException(errMsg);
        }

        SignalProtocolAddress address = new SignalProtocolAddress(senderId, senderDeviceId);
        SessionCipher cipher = new SessionCipher(store, address);
        PreKeySignalMessage preKeyMessage = new PreKeySignalMessage(ciphertext);
        byte[] plaintextBytes = cipher.decrypt(preKeyMessage);

        // Save updated session explicitly
        SessionRecord updatedSession = store.loadSession(address);
        store.storeSession(address, updatedSession);

        String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
        logger.info("{} Decrypted PreKey message from {} device {}", LOG_PREFIX, senderId, senderDeviceId);
        return plaintext;
    }


    public String decryptMessage(String senderId, int senderDeviceId, byte[] ciphertext) throws Exception {
        if (!hasSession(senderId, senderDeviceId)) {
            String errMsg = LOG_PREFIX + " No session found with " + senderId + ":" + senderDeviceId + " for message decryption.";
            logger.error(errMsg);
            throw new IllegalStateException(errMsg);
        }

        SignalProtocolAddress address = new SignalProtocolAddress(senderId, senderDeviceId);
        SessionCipher cipher = new SessionCipher(store, address);
        SignalMessage message = new SignalMessage(ciphertext);
        byte[] plaintextBytes = cipher.decrypt(message);

        // Explicitly save updated session after decryption
        SessionRecord updatedSession = store.loadSession(address);
        store.storeSession(address, updatedSession);

        String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
        logger.info("{} Decrypted message from {} device {}", LOG_PREFIX, senderId, senderDeviceId);
        return plaintext;
    }
}
