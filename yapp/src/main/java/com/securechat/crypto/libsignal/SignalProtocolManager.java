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

/**
 * {@code SignalProtocolManager} provides a high-level interface for managing
 * end-to-end encrypted communication using the Signal Protocol via libsignal.
 * <p>
 * This class wraps the libsignal functionality and ensures secure session handling,
 * encryption, and decryption of messages across devices.
 * It manages session state persistence, PreKey message handling, and
 * logs critical cryptographic events.
 * </p>
 *
 * <p>Typical usage involves:</p>
 * <ul>
 *   <li>Initializing sessions using PreKey bundles</li>
 *   <li>Encrypting messages using established sessions</li>
 *   <li>Decrypting incoming messages</li>
 * </ul>
 *
 * @author bhickensalsa
 * @version 0.1
 */
public class SignalProtocolManager {

    private static final Logger logger = LoggerFactory.getLogger(SignalProtocolManager.class);
    private static final String LOG_PREFIX = "[SignalProtocolManager]";

    private final SignalProtocolStore store;

    /**
     * Constructs a new {@code SignalProtocolManager} using the provided {@link SignalProtocolStore}.
     *
     * @param store the protocol store used to manage identity keys, sessions, and prekeys
     */
    public SignalProtocolManager(SignalProtocolStore store) {
        this.store = store;
        logger.debug("{} Created with provided SignalProtocolStore", LOG_PREFIX);
    }

    /**
     * Retrieves the underlying {@link SignalProtocolStore}.
     *
     * @return the store managing cryptographic state
     */
    public SignalProtocolStore getStore() {
        return store;
    }

    /**
     * Initializes a new Signal session with a remote peer using their {@link PreKeyBundle}.
     * <p>This is typically called when sending a message to a user for the first time.</p>
     *
     * @param peerId the unique identifier of the peer (e.g., username or UUID)
     * @param bundle the PreKeyBundle containing the peer's public identity and ephemeral keys
     * @throws InvalidKeyException if the bundle is invalid or cannot be processed
     */
    public void initializeSession(String peerId, PreKeyBundle bundle) throws InvalidKeyException {
        SignalProtocolAddress address = new SignalProtocolAddress(peerId, bundle.getDeviceId());
        SessionBuilder builder = new SessionBuilder(store, address);

        try {
            builder.process(bundle);

            SessionRecord updatedSession = store.loadSession(address);
            store.storeSession(address, updatedSession);

            logger.info("{} Initialized and saved session with peer {} device {}", LOG_PREFIX, peerId, bundle.getDeviceId());
        } catch (Exception e) {
            logger.error("{} Failed to process PreKeyBundle for peer {} device {}: {}", LOG_PREFIX, peerId, bundle.getDeviceId(), e.getMessage(), e);
            throw new InvalidKeyException("Failed to process PreKeyBundle", e);
        }
    }

    /**
     * Determines whether a session already exists with the given peer and device.
     *
     * @param peerId   the identifier of the peer
     * @param deviceId the ID of the peer's device
     * @return {@code true} if a valid session exists, {@code false} otherwise
     */
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

    /**
     * Encrypts a plaintext message using an existing session with a peer.
     *
     * @param peerId    the recipient's user ID
     * @param deviceId  the recipient's device ID
     * @param plaintext the message content to encrypt
     * @return the encrypted message as a byte array
     * @throws Exception if no session exists or encryption fails
     */
    public byte[] encryptMessage(String peerId, int deviceId, String plaintext) throws Exception {
        if (!hasSession(peerId, deviceId)) {
            String errMsg = LOG_PREFIX + " No session exists with " + peerId + ":" + deviceId + " for message encryption.";
            logger.error(errMsg);
            throw new IllegalStateException(errMsg);
        }

        SignalProtocolAddress address = new SignalProtocolAddress(peerId, deviceId);
        SessionCipher cipher = new SessionCipher(store, address);
        CiphertextMessage message = cipher.encrypt(plaintext.getBytes(StandardCharsets.UTF_8));

        SessionRecord updatedSession = store.loadSession(address);
        store.storeSession(address, updatedSession);

        logger.info("{} Encrypted message for peer {} device {}", LOG_PREFIX, peerId, deviceId);
        return message.serialize();
    }

    /**
     * Encrypts a message using PreKey cryptography, typically for the first message sent
     * when no session has been established.
     *
     * @param peerId    the recipient's user ID
     * @param deviceId  the recipient's device ID
     * @param plaintext the message to encrypt
     * @return the encrypted PreKey message as a byte array
     * @throws Exception if encryption fails
     */
    public byte[] encryptPreKeyMessage(String peerId, int deviceId, String plaintext) throws Exception {
        SignalProtocolAddress address = new SignalProtocolAddress(peerId, deviceId);
        SessionCipher cipher = new SessionCipher(store, address);
        CiphertextMessage message = cipher.encrypt(plaintext.getBytes(StandardCharsets.UTF_8));

        SessionRecord updatedSession = store.loadSession(address);
        store.storeSession(address, updatedSession);

        logger.info("{} Encrypted PreKey message for peer {} device {}", LOG_PREFIX, peerId, deviceId);
        return message.serialize();
    }

    /**
     * Decrypts a PreKeySignalMessage received from a remote peer.
     * <p>This should be used for messages received at the beginning of a session.</p>
     *
     * @param senderId        the sender's user ID
     * @param senderDeviceId  the sender's device ID
     * @param ciphertext      the encrypted message bytes
     * @return the plaintext message content
     * @throws Exception if no session is found or decryption fails
     */
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

        SessionRecord updatedSession = store.loadSession(address);
        store.storeSession(address, updatedSession);

        String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
        logger.info("{} Decrypted PreKey message from {} device {}", LOG_PREFIX, senderId, senderDeviceId);
        return plaintext;
    }

    /**
     * Decrypts a standard Signal message from an established session.
     *
     * @param senderId        the sender's user ID
     * @param senderDeviceId  the sender's device ID
     * @param ciphertext      the encrypted Signal message
     * @return the decrypted plaintext
     * @throws Exception if session is missing or message decryption fails
     */
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

        SessionRecord updatedSession = store.loadSession(address);
        store.storeSession(address, updatedSession);

        String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
        logger.info("{} Decrypted message from {} device {}", LOG_PREFIX, senderId, senderDeviceId);
        return plaintext;
    }
}
