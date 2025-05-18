package com.securechat.network;

import com.securechat.protocol.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Routes messages and manages peer connections per user and device.
 */
public class MessageRouter {

    private static final Logger logger = LoggerFactory.getLogger(MessageRouter.class);

    /**
     * Maps userId -> (deviceId -> PeerConnection)
     */
    private final Map<String, Map<Integer, PeerConnection>> activePeers = new ConcurrentHashMap<>();

    /**
     * Registers a peer connection for a specific user and device.
     *
     * @param userId     the user's unique ID
     * @param deviceId   the device ID
     * @param connection the peer connection to manage
     */
    public void registerPeer(String userId, int deviceId, PeerConnection connection) {
        activePeers.computeIfAbsent(userId, k -> new ConcurrentHashMap<>())
                   .put(deviceId, connection);
        logger.info("Registered peer for user '{}' on device {}", userId, deviceId);
    }

    /**
     * Routes a message to the specific recipient and device.
     *
     * @param packet     the packet to route
     * @param senderId   the sender's user ID
     */
    public void routeMessage(Packet packet, String senderId) {
        if (packet == null || packet.getRecipientId() == null) {
            logger.warn("Invalid packet or recipientId; message dropped.");
            return;
        }

        String recipientId = packet.getRecipientId();
        int recipientDeviceId = packet.getRecipientDeviceId();

        PeerConnection recipientConn = getConnection(recipientId, recipientDeviceId);
        if (recipientConn != null) {
            try {
                recipientConn.sendMessageObject(packet);
                logger.debug("Routed message from '{}' to '{}@{}'", senderId, recipientId, recipientDeviceId);
            } catch (Exception e) {
                logger.error("Failed to send message to '{}@{}'", recipientId, recipientDeviceId, e);
            }
        } else {
            logger.warn("No connection for recipient '{}@{}'; packet dropped.", recipientId, recipientDeviceId);
        }
    }

    /**
     * Routes a PreKey-related packet.
     *
     * @param packet      the packet containing the PreKey bundle
     * @param recipientId the user ID of the recipient
     * @param deviceId    the target device ID
     */
    public void routePreKeyPacket(Packet packet, String recipientId, int deviceId) {
        if (packet == null || recipientId == null || packet.getPreKeyBundlePayload() == null) {
            logger.warn("Invalid PreKey packet or missing payload; dropped.");
            return;
        }

        PeerConnection conn = getConnection(recipientId, deviceId);
        if (conn != null) {
            try {
                conn.sendMessageObject(packet);
                logger.debug("Routed PreKey packet to '{}@{}'", recipientId, deviceId);
            } catch (Exception e) {
                logger.error("Failed to route PreKey packet to '{}@{}'", recipientId, deviceId, e);
            }
        } else {
            logger.warn("No connection found for '{}@{}'; PreKey packet dropped.", recipientId, deviceId);
        }
    }

    /**
     * Unregisters all devices for a given user and closes all associated connections.
     *
     * @param userId the user to unregister
     */
    public void unregisterPeer(String userId) {
        Map<Integer, PeerConnection> connections = activePeers.remove(userId);
        if (connections != null) {
            connections.forEach((deviceId, conn) -> {
                try {
                    conn.close();
                    logger.info("Closed connection for '{}@{}'", userId, deviceId);
                } catch (Exception e) {
                    logger.warn("Error closing connection for '{}@{}'", userId, deviceId, e);
                }
            });
        } else {
            logger.info("No active connections to unregister for '{}'", userId);
        }
    }

    /**
     * Unregisters a specific device for a user.
     *
     * @param userId   the user ID
     * @param deviceId the device ID
     */
    public void unregisterPeerDevice(String userId, int deviceId) {
        Map<Integer, PeerConnection> devices = activePeers.get(userId);
        if (devices != null) {
            PeerConnection conn = devices.remove(deviceId);
            if (conn != null) {
                try {
                    conn.close();
                    logger.info("Unregistered device {} for user '{}'", deviceId, userId);
                } catch (Exception e) {
                    logger.warn("Failed to close connection for '{}@{}'", userId, deviceId, e);
                }
            }
            if (devices.isEmpty()) {
                activePeers.remove(userId);
            }
        }
    }

    /**
     * Retrieves a connection for a specific user and device.
     *
     * @param userId   the user ID
     * @param deviceId the device ID
     * @return the peer connection if active; otherwise null
     */
    private PeerConnection getConnection(String userId, int deviceId) {
        Map<Integer, PeerConnection> devices = activePeers.get(userId);
        return devices != null ? devices.get(deviceId) : null;
    }
}
