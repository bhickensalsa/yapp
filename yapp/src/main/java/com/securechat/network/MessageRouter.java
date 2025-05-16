package com.securechat.network;

import com.securechat.protocol.Message;
import com.securechat.protocol.Packet;
import com.securechat.protocol.PacketType;

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
     * The message parameter here is expected to be the deserialized Message object,
     * wrapped as a Packet elsewhere (so this method sends just the Message).
     */
    public void routeMessage(Message message) {
        PeerConnection recipientConnection = activeUsers.get(message.getRecipient());

        if (recipientConnection != null) {
            try {
                // Use the message stream to send the message Packet
                Packet packet = new Packet(PacketType.MESSAGE, message);
                recipientConnection.sendMessageObject(packet);
                logger.debug("Routed message from '{}' to '{}'", message.getSender(), message.getRecipient());
            } catch (Exception e) {
                logger.error("Failed to send message to user '{}'", message.getRecipient(), e);
            }
        } else {
            logger.warn("No active connection found for recipient '{}'. Message from '{}' dropped.",
                        message.getRecipient(), message.getSender());
        }
    }

    /**
     * Routes prekey-related packets (e.g., PreKeyBundle requests/responses) over the prekey stream.
     */
    public void routePreKeyPacket(Packet preKeyPacket, String recipientId) {
        PeerConnection recipientConnection = activeUsers.get(recipientId);

        if (recipientConnection != null) {
            try {
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
