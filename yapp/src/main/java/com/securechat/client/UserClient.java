package com.securechat.client;

import com.securechat.crypto.libsignal.*;
import com.securechat.network.PeerConnection;
import com.securechat.protocol.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.PreKeyBundle;

import java.net.Socket;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class UserClient {
    private static final Logger logger = LoggerFactory.getLogger(UserClient.class);

    private final String userId;
    private final int deviceId;
    private final SignalKeyStore keyStore;
    private final SignalProtocolManager cryptoManager;

    private final int preKeyId;
    private final int signedPreKeyId;

    private PeerConnection connection;
    private PreKeyBundle myBundle;

    // Thread-safe map for peer device tracking
    private final Map<String, Integer> peerDeviceIds = new ConcurrentHashMap<>();

    public UserClient(String userId, int deviceId, SignalKeyStore keyStore, int preKeyId, int signedPreKeyId) {
        this.userId = userId;
        this.deviceId = deviceId;
        this.keyStore = keyStore;
        this.cryptoManager = new SignalProtocolManager(keyStore);
        this.preKeyId = preKeyId;
        this.signedPreKeyId = signedPreKeyId;
    }

    public void connectToServer(String host, int messagePort, int preKeyPort) {
        try {
            Socket messageSocket = new Socket(host, messagePort);
            Socket preKeySocket = new Socket(host, preKeyPort);
            this.connection = new PeerConnection(messageSocket, preKeySocket);

            connection.sendMessageObject(userId);

            myBundle = PreKeyBundleBuilder.build(
                    keyStore.getLocalRegistrationId(), deviceId,
                    keyStore, preKeyId, signedPreKeyId
            );
            PreKeyBundleDTO dto = PreKeyBundleDTO.fromPreKeyBundle(myBundle);
            connection.sendPreKeyObject(new Packet(PacketType.PREKEY_BUNDLE, dto));

            logger.info("Registered prekey bundle with server as '{}'", userId);
        } catch (Exception e) {
            logger.error("Connection or registration failed: {}", e.getMessage(), e);
        }
    }

    public boolean establishSessionWith(String peerId) {
        try {
            if (cryptoManager.hasSession(peerId)) {
                logger.info("Session with {} already exists", peerId);
                return true;
            }

            connection.sendPreKeyObject(new Packet(PacketType.GET_PREKEY_BUNDLE, peerId));
            Object obj = connection.receivePreKeyObject();

            if (!(obj instanceof Packet response)) {
                logger.warn("Unexpected response on prekey stream: {}", obj);
                return false;
            }

            if (response.getType() == PacketType.PREKEY_BUNDLE && response.getPayload() instanceof PreKeyBundleDTO dto) {
                PreKeyBundle bundle = dto.toPreKeyBundle();
                if (bundle == null || bundle.getIdentityKey() == null || bundle.getSignedPreKey() == null) {
                    logger.error("Invalid or incomplete PreKeyBundle received from {}", peerId);
                    return false;
                }

                int peerDeviceId = bundle.getDeviceId();
                peerDeviceIds.put(peerId, peerDeviceId);
                SignalProtocolAddress peerAddress = new SignalProtocolAddress(peerId, peerDeviceId);

                cryptoManager.initializeSession(peerAddress, bundle);
                logger.info("Session established with {}", peerId);
                return true;
            }

            if (response.getType() == PacketType.ERROR) {
                logger.error("PreKey error from server: {}", response.getPayload());
            } else {
                logger.warn("Unexpected packet type during session setup: {}", response.getType());
            }

        } catch (Exception e) {
            logger.error("Failed to establish session with {}: {}", peerId, e.getMessage(), e);
        }
        return false;
    }

    public boolean sendMessage(String recipientId, String plaintext) {
        Integer peerDeviceId = peerDeviceIds.get(recipientId);
        if (peerDeviceId == null) {
            logger.warn("Session with {} not established. Call establishSessionWith() first.", recipientId);
            return false;
        }

        try {
            SignalProtocolAddress recipientAddress = new SignalProtocolAddress(recipientId, peerDeviceId);
            boolean hasSession = keyStore.containsSession(recipientAddress);

            EncryptedMessageResult encrypted = cryptoManager.encryptMessage(recipientAddress, plaintext);
            if (encrypted == null || encrypted.ciphertext() == null) {
                logger.error("Encryption failed for {}", recipientId);
                return false;
            }

            MessageType type = hasSession ? MessageType.CIPHERTEXT : MessageType.PREKEY;
            sendEncryptedMessage(recipientId, encrypted.ciphertext(), type, !hasSession);

            return true;
        } catch (Exception e) {
            logger.error("Message sending failed to {}: {}", recipientId, e.getMessage(), e);
            return false;
        }
    }

    private void sendEncryptedMessage(String recipientId, byte[] ciphertext, MessageType type, boolean isPreKeyMessage) {
        try {
            String encoded = Base64.getEncoder().encodeToString(ciphertext);
            Message msg = new Message(UUID.randomUUID().toString(), userId, recipientId, type, encoded, isPreKeyMessage);
            connection.sendMessageObject(new Packet(PacketType.MESSAGE, msg));

            logger.info("Sent {} message to {} (preKey: {})", type, recipientId, isPreKeyMessage);
        } catch (Exception e) {
            logger.error("Failed to send encrypted message to {}: {}", recipientId, e.getMessage(), e);
        }
    }

    public void listen() {
        new Thread(() -> {
            try {
                while (true) {
                    Object obj = connection.receiveMessageObject();
                    if (!(obj instanceof Packet packet)) {
                        logger.warn("Invalid object received: {}", obj);
                        continue;
                    }

                    if (packet.getType() == PacketType.MESSAGE && packet.getPayload() instanceof Message msg) {
                        logger.info("Message from {} (type {}):", msg.getSender(), msg.getMessageType());

                        Integer deviceId = peerDeviceIds.get(msg.getSender());
                        if (deviceId == null) {
                            logger.warn("Unknown deviceId for sender {}", msg.getSender());
                            continue;
                        }

                        SignalProtocolAddress senderAddress = new SignalProtocolAddress(msg.getSender(), deviceId);
                        byte[] ciphertext = Base64.getDecoder().decode(msg.getEncryptedPayload());

                        try {
                            String plaintext = cryptoManager.decryptAny(senderAddress, ciphertext);
                            logger.info("Decrypted message: {}", plaintext);
                        } catch (Exception e) {
                            logger.error("Decryption failed from {}: {}", msg.getSender(), e.getMessage(), e);
                        }
                    } else {
                        logger.warn("Unsupported packet or invalid payload: {}", packet.getType());
                    }
                }
            } catch (Exception e) {
                logger.error("Listener stopped due to exception: {}", e.getMessage(), e);
            }
        }, "UserClient-Listener-" + userId).start();
    }
}
