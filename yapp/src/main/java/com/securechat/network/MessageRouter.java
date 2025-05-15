package com.securechat.network;

import com.securechat.protocol.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class MessageRouter {

    private static final Logger logger = LoggerFactory.getLogger(MessageRouter.class);

    // Maps userId to the PeerConnection for sending messages
    private final Map<String, PeerConnection> activeUsers = new ConcurrentHashMap<>();

    public void registerPeer(String userId, PeerConnection connection) {
        activeUsers.put(userId, connection);
        logger.info("Registered peer connection for user '{}'", userId);
    }

    public void routeMessage(Message message) {
        PeerConnection recipientConnection = activeUsers.get(message.getRecipient());

        if (recipientConnection != null) {
            try {
                recipientConnection.sendObject(message);
                logger.debug("Routed message from '{}' to '{}'", message.getSender(), message.getRecipient());
            } catch (Exception e) {
                logger.error("Failed to send message to user '{}'", message.getRecipient(), e);
            }
        } else {
            logger.warn("No active connection found for recipient '{}'. Message from '{}' dropped.",
                        message.getRecipient(), message.getSender());
        }
    }

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
