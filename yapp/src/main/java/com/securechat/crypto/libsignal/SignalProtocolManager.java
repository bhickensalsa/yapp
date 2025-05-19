package com.securechat.crypto.libsignal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.util.HashMap;
import java.util.Map;

public class SignalProtocolManager {

    private static final Logger logger = LoggerFactory.getLogger(SignalProtocolManager.class);
    private static final String LOG_PREFIX = "[SignalProtocolManager]";

    private final SignalProtocolStore store;
    private final Map<String, SessionBuilder> sessionBuilders = new HashMap<>();

    public SignalProtocolManager(SignalProtocolStore store) {
        this.store = store;
        logger.debug("{} SignalProtocolManager created with provided store", LOG_PREFIX);
    }

    private String sessionKey(String peerId, int deviceId) {
        return peerId + ":" + deviceId;
    }

    /**
     * Initialize or update a session with a peer's PreKeyBundle (used in session establishment)
     */
    public void initializeSession(String peerId, PreKeyBundle bundle) throws InvalidKeyException {
        SignalProtocolAddress address = new SignalProtocolAddress(peerId, bundle.getDeviceId());
        SessionBuilder builder = new SessionBuilder(store, address);
        try {
            builder.process(bundle);
            sessionBuilders.put(sessionKey(peerId, bundle.getDeviceId()), builder);
            logger.info("{} Initialized session with peer {} device {}", LOG_PREFIX, peerId, bundle.getDeviceId());
        } catch (Exception e) {
            logger.error("{} Failed to process PreKeyBundle for peer {} device {}: {}", LOG_PREFIX, peerId, bundle.getDeviceId(), e.toString());
            throw new InvalidKeyException("Failed to process PreKeyBundle", e);
        }
    }

    /**
     * Checks if a session exists with the given peer device
     */
    public boolean hasSession(String peerId, int deviceId) {
        SignalProtocolAddress address = new SignalProtocolAddress(peerId, deviceId);
        try {
            SessionRecord record = store.loadSession(address);
            boolean exists = record != null && record.getSessionState().getSessionVersion() > 0;
            logger.debug("{} Session existence check for peer {} device {}: {}", LOG_PREFIX, peerId, deviceId, exists);
            return exists;
        } catch (Exception e) {
            logger.warn("{} Exception while checking session for peer {} device {}: {}", LOG_PREFIX, peerId, deviceId, e.toString());
            return false;
        }
    }

    /**
     * Encrypt a message assuming a session exists (normal message)
     */
    public byte[] encryptMessage(String peerId, int deviceId, String plaintext) throws Exception {
        SignalProtocolAddress address = new SignalProtocolAddress(peerId, deviceId);

        if (!hasSession(peerId, deviceId)) {
            String errMsg = LOG_PREFIX + " No session found with " + peerId + ":" + deviceId;
            logger.error(errMsg);
            throw new IllegalStateException(errMsg);
        }

        SessionCipher cipher = new SessionCipher(store, address);
        CiphertextMessage message = cipher.encrypt(plaintext.getBytes(StandardCharsets.UTF_8));
        logger.info("{} Encrypted message for peer {} device {}", LOG_PREFIX, peerId, deviceId);
        return message.serialize();
    }

    /**
     * Encrypt a message as a PreKeySignalMessage (session not established yet)
     * Usually used before session is established
     */
    public byte[] encryptPreKeyMessage(String peerId, int deviceId, String plaintext) throws Exception {
        SignalProtocolAddress address = new SignalProtocolAddress(peerId, deviceId);
        SessionCipher cipher = new SessionCipher(store, address);

        CiphertextMessage message = cipher.encrypt(plaintext.getBytes(StandardCharsets.UTF_8));
        logger.info("{} Encrypted PreKey message for peer {} device {}", LOG_PREFIX, peerId, deviceId);
        return message.serialize();
    }

    /**
     * Decrypt a PreKeyMessage (initial session message)
     */
    public String decryptPreKeyMessage(SignalProtocolAddress senderAddress, byte[] ciphertext) throws Exception {
        SessionCipher cipher = new SessionCipher(store, senderAddress);

        PreKeySignalMessage preKeyMessage = new PreKeySignalMessage(ciphertext);
        byte[] plaintextBytes = cipher.decrypt(preKeyMessage);
        String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
        logger.info("{} Decrypted PreKey message from {} device {}", LOG_PREFIX, senderAddress.getName(), senderAddress.getDeviceId());
        return plaintext;
    }

    /**
     * Decrypt a normal message
     */
    public String decryptMessage(String senderId, int senderDeviceId, byte[] ciphertext) throws Exception {
        SignalProtocolAddress address = new SignalProtocolAddress(senderId, senderDeviceId);
        SessionCipher cipher = new SessionCipher(store, address);

        SignalMessage message = new SignalMessage(ciphertext);
        byte[] plaintextBytes = cipher.decrypt(message);
        String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
        logger.info("{} Decrypted message from {} device {}", LOG_PREFIX, senderId, senderDeviceId);
        return plaintext;
    }
}
