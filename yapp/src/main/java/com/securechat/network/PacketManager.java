package com.securechat.network;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.securechat.crypto.libsignal.SignalProtocolManager;
import com.securechat.protocol.Packet;
import com.securechat.protocol.PacketType;

/**
 * Manages sending, receiving, and processing of encrypted packets for a user's device.
 *
 * <p>This class listens for incoming packets from a peer connection, handles
 * decryption and processing based on packet type, and supports sending encrypted
 * messages and acknowledgments. It uses a dedicated single-threaded executor
 * to process incoming packets asynchronously.
 *
 * <p>Pending requests (such as PreKey bundle retrievals) are tracked using
 * CompletableFutures to support asynchronous workflows.
 * 
 * @author bhickensalsa
 * @version 0.2
 */
public class PacketManager {
    private static final Logger logger = LoggerFactory.getLogger(PacketManager.class);

    private final String userId;
    private final int userDeviceId;
    private final PeerConnection connection;
    private final SignalProtocolManager SPManager;
    private final ExecutorService pool;
    private final Map<String, CompletableFuture<Packet>> pendingRequests;

    private DecryptedMessageListener decryptedMessageListener;
    private UserStatusUpdateListener userStatusUpdateListener;

    /**
     * Constructs a PacketManager for the specified user device, managing
     * communication via the provided PeerConnection and SignalProtocolManager.
     *
     * @param userId          the user ID associated with this PacketManager (non-null)
     * @param userDeviceId    the device ID for the user
     * @param connection      the active PeerConnection for sending/receiving packets (non-null)
     * @param SPManager       the SignalProtocolManager used for encryption/decryption (non-null)
     * @param pendingRequests a map tracking pending CompletableFuture responses keyed by unique request IDs (non-null)
     */
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
    
    public void setDecryptedMessageListener(DecryptedMessageListener listener) {
        this.decryptedMessageListener = listener;
    }
    
    /**
     * Sets the listener for user status updates.
     *
     * @param listener the listener to receive status updates
     */
    public void setStatusUpdateListener(UserStatusUpdateListener listener) {
        this.userStatusUpdateListener = listener;
    }

    private void notifyGuiUserStatusUpdate(String updateMsg) {
        if (userStatusUpdateListener != null) {
            userStatusUpdateListener.onUserStatusUpdate(updateMsg);
        }
    }

    /**
     * Starts listening for incoming packets on a background thread.
     * Incoming objects received from the PeerConnection are expected to be
     * {@link Packet} instances, which will be processed accordingly.
     *
     * <p>This method returns immediately; processing happens asynchronously.
     */
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

    /**
     * Sends an encrypted message packet of the specified type to the given peer device.
     *
     * @param peerId       the recipient user's ID (non-null)
     * @param peerDeviceId the recipient device ID
     * @param message      the plaintext message to send (non-null)
     * @param type         the packet type; must be PREKEY_MESSAGE or MESSAGE
     */
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

    /**
     * Sends an acknowledgment (ACK) packet to the specified peer device.
     *
     * @param peerId       the recipient user's ID (non-null)
     * @param peerDeviceId the recipient device ID
     */
    public void sendAck(String peerId, int peerDeviceId) {
        try {
            Packet ack = new Packet(userId, userDeviceId, peerId, peerDeviceId, null, PacketType.ACK);
            connection.sendMessageObject(ack);
            logger.info("[{}] Sent ACK to {}:{}", userId, peerId, peerDeviceId);
        } catch (Exception e) {
            logger.error("[{}] Failed to send ACK to {}:{}", userId, peerId, peerDeviceId, e);
        }
    }


    /**
     * Stops listening for incoming packets and shuts down the internal thread pool.
     * Once shut down, this PacketManager will no longer process incoming packets.
     */
    public void shutdown() {
        pool.shutdownNow();
        logger.info("[{}] PacketManager listener shutdown", userId);
    }

    /**
     * Internal method to process an incoming packet based on its type.
     *
     * @param packet the received packet (non-null)
     */
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
                    if (decryptedMessageListener != null) {
                        decryptedMessageListener.onDecryptedMessage(senderId, senderDeviceId, plaintext);
                    }
                }

                case MESSAGE -> {
                    if (!SPManager.hasSession(senderId, senderDeviceId)) {
                        logger.warn("[{}] Received MESSAGE from {} without session, ignoring", userId, senderKey);
                        return;
                    }
                    String plaintext = SPManager.decryptMessage(senderId, senderDeviceId, packet.getMessagePayload());
                    logger.info("[{}] Received MESSAGE from {}: {}", userId, senderKey, plaintext);
                    if (decryptedMessageListener != null) {
                        decryptedMessageListener.onDecryptedMessage(senderId, senderDeviceId, plaintext);
                    }
                }

                case ACK -> {
                    logger.info("[{}] Received ACK from {}", userId, senderKey);
                }

                case ERROR -> {
                    String errorMsg = new String(packet.getMessagePayload(), StandardCharsets.UTF_8);
                    logger.error("[{}] Received ERROR packet from {}: {}", userId, senderKey, errorMsg);
                    // Future: map error to pending request or notify listener
                }

                case COMMAND -> {
                    String command = new String(packet.getMessagePayload(), StandardCharsets.UTF_8);
                    logger.info("[{}] Received COMMAND from {}: {}", userId, senderKey, command);
                    // Optional: forward to command handler
                }

                case GET_PREKEY_BUNDLE -> {
                    logger.warn("[{}] Received unexpected GET_PREKEY_BUNDLE from {}", userId, senderKey);
                    // Typically sent to server, not expected from peer
                }

                case USER_CONNECTED -> {
                    String updateMsg = new String(packet.getMessagePayload(), StandardCharsets.UTF_8);
                    logger.info("[{}] Update: {}", userId, updateMsg);
                    notifyGuiUserStatusUpdate(updateMsg);
                }

                case USER_DISCONNECTED -> {
                    String updateMsg = new String(packet.getMessagePayload(), StandardCharsets.UTF_8);
                    logger.info("[{}] Update: {}", userId, updateMsg);
                    notifyGuiUserStatusUpdate(updateMsg);
                }

                default -> {
                    logger.warn("[{}] Unhandled packet type {} from {}", userId, packet.getType(), senderKey);
                }
            }
        } catch (Exception e) {
            logger.error("[{}] Error processing packet from {}: {}", userId, senderKey, e.getMessage(), e);
        }
    }
}
