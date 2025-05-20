package com.securechat.network;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.securechat.crypto.libsignal.SignalProtocolManager;
import com.securechat.protocol.Packet;
import com.securechat.protocol.PacketType;

public class PacketManager {
    private static final Logger logger = LoggerFactory.getLogger(PacketManager.class);

    private final String userId;
    private final int userDeviceId;
    private final PeerConnection connection;
    private final SignalProtocolManager SPManager;
    private final ExecutorService pool;
    private final Map<String, CompletableFuture<Packet>> pendingRequests;

    public PacketManager(String userId, int userDeviceId,
                         PeerConnection connection,
                         SignalProtocolManager SPManager,
                         Map<String, CompletableFuture<Packet>> pendingRequests) {
        this.userId = userId;
        this.userDeviceId = userDeviceId;
        this.connection = connection;
        this.SPManager = SPManager;
        this.pendingRequests = pendingRequests;
        this.pool = Executors.newSingleThreadExecutor();
    }

    public void startListening() {
        logger.info("[{}] PacketManager started listening", userId);
        pool.submit(() -> {
            try {
                while (!Thread.currentThread().isInterrupted()) {
                    Object obj = connection.receiveMessageObject();
                    if (obj instanceof Packet packet) {
                        handleIncomingPacket(packet);
                    } else {
                        logger.warn("[{}] Received unknown object type: {}", userId, obj);
                    }
                }
            } catch (Exception e) {
                logger.error("[{}] Listening error", userId, e);
            }
        });
    }

    private void handleIncomingPacket(Packet packet) {
        String senderId = packet.getSenderId();
        int senderDeviceId = packet.getSenderDeviceId();
        String senderKey = senderId + ":" + senderDeviceId;

        try {
            switch (packet.getType()) {
                case PREKEY_BUNDLE -> {
                    String key = senderId + ":" + PacketType.PREKEY_BUNDLE.name();
                    CompletableFuture<Packet> future = pendingRequests.remove(key);
                    if (future != null) {
                        future.complete(packet);
                        logger.info("[{}] Received PREKEY_BUNDLE from {}", userId, senderKey);
                    } else {
                        logger.warn("[{}] No pending request for PREKEY_BUNDLE from {}", userId, senderKey);
                    }
                }

                case PREKEY_MESSAGE -> {
                    String plaintext = SPManager.decryptPreKeyMessage(senderId, senderDeviceId, packet.getMessagePayload());
                    logger.info("[{}] Received PREKEY_MESSAGE from {}: {}", userId, senderKey, plaintext);
                    sendAck(senderId, senderDeviceId);
                }

                case MESSAGE -> {
                    if (!SPManager.hasSession(senderId, senderDeviceId)) {
                        logger.warn("[{}] Received MESSAGE from {} without session, ignoring", userId, senderKey);
                        return;
                    }
                    String plaintext = SPManager.decryptMessage(senderId, senderDeviceId, packet.getMessagePayload());
                    logger.info("[{}] Received MESSAGE from {}: {}", userId, senderKey, plaintext);
                }

                case ACK -> {
                    logger.info("[{}] Received ACK from {}", userId, senderKey);
                }

                case ERROR -> {
                    String errorMsg = new String(packet.getMessagePayload()); // assuming it's just a UTF-8 string
                    logger.error("[{}] Received ERROR packet from {}: {}", userId, senderKey, errorMsg);
                    // Future enhancement: map to pending request or notify listener
                }

                case COMMAND -> {
                    String command = new String(packet.getMessagePayload());
                    logger.info("[{}] Received COMMAND from {}: {}", userId, senderKey, command);
                    // Optionally, forward to helper class for execution
                    //CommandHandler.handle(userId, senderId, command); // Maybe implement in a new client helper/util class
                }

                case GET_PREKEY_BUNDLE -> {
                    logger.warn("[{}] Received unexpected GET_PREKEY_BUNDLE from {}", userId, senderKey);
                    // Usually sent *to* server, not expected *from* peer
                }

                default -> {
                    logger.warn("[{}] Unhandled packet type {} from {}", userId, packet.getType(), senderKey);
                }
            }
        } catch (Exception e) {
            logger.error("[{}] Error processing packet from {}: {}", userId, senderKey, e.getMessage(), e);
        }
    }


    public void sendMessage(String peerId, int peerDeviceId, String message, PacketType type) {
        try {
            byte[] encrypted = switch (type) {
                case PREKEY_MESSAGE -> SPManager.encryptPreKeyMessage(peerId, peerDeviceId, message);
                case MESSAGE -> SPManager.encryptMessage(peerId, peerDeviceId, message);
                default -> throw new IllegalArgumentException("Unsupported packet type: " + type);
            };

            Packet packet = new Packet(userId, userDeviceId, peerId, peerDeviceId, encrypted, type);
            connection.sendMessageObject(packet);

            logger.info("[{}] Sent {} to {}", userId, type, peerId);
        } catch (Exception e) {
            logger.error("[{}] Failed to send {} to {}: {}", userId, type, peerId, e.getMessage(), e);
        }
    }

    public void sendAck(String peerId, int peerDeviceId) {
        try {
            Packet ack = new Packet(userId, userDeviceId, peerId, peerDeviceId, null, PacketType.ACK);
            connection.sendMessageObject(ack);
            logger.info("[{}] Sent ACK to {}:{}", userId, peerId, peerDeviceId);
        } catch (Exception e) {
            logger.error("[{}] Failed to send ACK to {}:{}", userId, peerId, peerDeviceId, e);
        }
    }

    public void shutdown() {
        pool.shutdownNow();
        logger.info("[{}] PacketManager listener shutdown", userId);
    }
}
