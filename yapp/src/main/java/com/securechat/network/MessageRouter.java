package com.securechat.network;

import com.securechat.protocol.Message;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class MessageRouter {

    private final Map<String, PeerConnection> connections = new ConcurrentHashMap<>();

    public void registerPeer(String userId, PeerConnection connection) {
        connections.put(userId, connection);
    }

    public void routeMessage(Message message) {
        PeerConnection recipient = connections.get(message.getRecipient());
        if (recipient != null) {
            try {
                recipient.send(message.toString()); // You might want to use MessageSerializer
            } catch (Exception e) {
                System.err.println("Failed to send message to " + message.getRecipient());
            }
        }
    }

    public void unregisterPeer(String userId) {
        connections.remove(userId);
    }
}
