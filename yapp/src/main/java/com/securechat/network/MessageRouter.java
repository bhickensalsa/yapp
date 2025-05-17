package com.securechat.network;

import com.securechat.protocol.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages active users and routes messages via their dedicated message and prekey connections.
 */
public class MessageRouter {

    private static final Logger logger = LoggerFactory.getLogger(MessageRouter.class);

    /**
     * Maps userId to their PeerConnection (which internally manages dual streams).
     */
    private final Map<String, PeerConnection> activeUsers = new ConcurrentHashMap<>();

    /**
     * Register a user with their dual-stream PeerConnection.
     */
    public void registerPeer(String userId, PeerConnection connection) {
        activeUsers.put(userId, connection);
        logger.info("Registered peer connection for user '{}'", userId);
    }

    /**
     * Routes a message packet to the recipient over their message stream.
     */
    public void routeMessage(Packet packet, String senderId) {
        if (packet == null) {
            logger.warn("Null packet");
            return;
        }

        String recipientId = packet.getRecipientId();
        if (recipientId == null) {
            logger.warn("Packet has no recipientId; dropping message");
            return;
        }

        byte[] messagePayload = packet.getMessagePayload();
        if (messagePayload == null) {
            logger.warn("Packet of type MESSAGE missing byte[] payload; dropping message");
            return;
        }

        PeerConnection recipientConnection = activeUsers.get(recipientId);
        if (recipientConnection != null) {
            try {
                // Assuming sendMessageObject accepts byte[] or Packet, here we pass the whole packet
                // but you might need to send just the messagePayload depending on PeerConnection API
                recipientConnection.sendMessageObject(packet);
                logger.debug("Routed ciphertext message from '{}' to '{}'", senderId, recipientId);
            } catch (Exception e) {
                logger.error("Failed to send ciphertext message to user '{}'", recipientId, e);
            }
        } else {
            logger.warn("No active connection found for recipient '{}'. Packet dropped.", recipientId);
        }
    }

    /**
     * Routes prekey-related packets (e.g., PreKeyBundle requests/responses) over the prekey stream.
     */
    public void routePreKeyPacket(Packet preKeyPacket, String recipientId) {
        if (preKeyPacket == null) {
            logger.warn("Null preKeyPacket");
            return;
        }

        PeerConnection recipientConnection = activeUsers.get(recipientId);

        if (recipientConnection != null) {
            try {
                // You can verify payload type here if you want
                if (preKeyPacket.getPreKeyBundlePayload() == null && preKeyPacket.getStringPayload() == null) {
                    logger.warn("PreKey packet has no valid payload, dropping");
                    return;
                }
                recipientConnection.sendPreKeyObject(preKeyPacket);
                logger.debug("Routed prekey packet of type '{}' to '{}'", preKeyPacket.getType(), recipientId);
            } catch (Exception e) {
                logger.error("Failed to send prekey packet to user '{}'", recipientId, e);
            }
        } else {
            logger.warn("No active connection found for recipient '{}'. Prekey packet dropped.", recipientId);
        }
    }

    /**
     * Unregisters a peer and closes their connection.
     */
    public void unregisterPeer(String userId) {
        PeerConnection conn = activeUsers.remove(userId);
        if (conn != null) {
            try {
                conn.close();
                logger.info("Closed connection and unregistered peer '{}'", userId);
            } catch (Exception e) {
                logger.warn("Failed to close connection for peer '{}'", userId, e);
            }
        } else {
            logger.info("Unregistered peer '{}'", userId);
        }
    }
}
