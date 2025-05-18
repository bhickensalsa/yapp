package com.securechat.crypto.libsignal;

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

    private final SignalProtocolStore store;
    private final Map<String, SessionBuilder> sessionBuilders = new HashMap<>();

    public SignalProtocolManager(SignalProtocolStore store) {
        this.store = store;
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
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to process PreKeyBundle", e);
        }
        sessionBuilders.put(sessionKey(peerId, bundle.getDeviceId()), builder);
    }

    /**
     * Checks if a session exists with the given peer device
     */
    public boolean hasSession(String peerId, int deviceId) {
        SignalProtocolAddress address = new SignalProtocolAddress(peerId, deviceId);
        try {
            SessionRecord record = store.loadSession(address);
            return record != null && record.getSessionState().getSessionVersion() > 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Encrypt a message assuming a session exists (normal message)
     */
    public byte[] encryptMessage(String peerId, int deviceId, String plaintext) throws Exception {
        SignalProtocolAddress address = new SignalProtocolAddress(peerId, deviceId);
        // Ensure session exists
        if (!hasSession(peerId, deviceId)) {
            throw new IllegalStateException("No session found with " + peerId + ":" + deviceId);
        }
        SessionCipher cipher = new SessionCipher(store, address);
        CiphertextMessage message = cipher.encrypt(plaintext.getBytes(StandardCharsets.UTF_8));
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
        return message.serialize();
    }

    /**
     * Decrypt a PreKeyMessage (initial session message)
     */
    public String decryptPreKeyMessage(String senderId, int senderDeviceId, byte[] ciphertext) throws Exception {
        SignalProtocolAddress address = new SignalProtocolAddress(senderId, senderDeviceId);
        SessionCipher cipher = new SessionCipher(store, address);

        PreKeySignalMessage preKeyMessage = new PreKeySignalMessage(ciphertext);
        byte[] plaintextBytes = cipher.decrypt(preKeyMessage);
        return new String(plaintextBytes, StandardCharsets.UTF_8);
    }

    /**
     * Decrypt a normal message
     */
    public String decryptMessage(String senderId, int senderDeviceId, byte[] ciphertext) throws Exception {
        SignalProtocolAddress address = new SignalProtocolAddress(senderId, senderDeviceId);
        SessionCipher cipher = new SessionCipher(store, address);

        SignalMessage message = new SignalMessage(ciphertext);
        byte[] plaintextBytes = cipher.decrypt(message);
        return new String(plaintextBytes, StandardCharsets.UTF_8);
    }
}
