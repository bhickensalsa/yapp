package com.securechat.network;

import com.securechat.protocol.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class MessageRouter {

    private static final Logger logger = LoggerFactory.getLogger(MessageRouter.class);

    private final Map<String, PeerConnection> connections = new ConcurrentHashMap<>();

    public void registerPeer(String userId, PeerConnection connection) {
        connections.put(userId, connection);
        logger.info("Registered peer connection for user '{}'", userId);
    }

    public void routeMessage(Message message) {
        PeerConnection recipient = connections.get(message.getRecipient());
        if (recipient != null) {
            try {
                // Assuming you want to use MessageSerializer for consistency:
                // recipient.send(MessageSerializer.serialize(message));
                recipient.send(message.toString());
                logger.debug("Routed message from '{}' to '{}'", message.getSender(), message.getRecipient());
            } catch (Exception e) {
                logger.error("Failed to send message to user '{}'", message.getRecipient(), e);
            }
        } else {
            logger.warn("No active connection found for recipient '{}'. Message from '{}' dropped.", message.getRecipient(), message.getSender());
        }
    }

    public void unregisterPeer(String userId) {
        connections.remove(userId);
        logger.info("Unregistered peer connection for user '{}'", userId);
    }
}
