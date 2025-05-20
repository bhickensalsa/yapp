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
        if (userId == null || connection == null || deviceId < 0) {
            logger.warn("Invalid parameters for registering peer: userId={}, deviceId={}", userId, deviceId);
            throw new IllegalArgumentException("Invalid parameters for registerPeer");
        }

        activePeers.compute(userId, (uid, devices) -> {
            if (devices == null) {
                devices = new ConcurrentHashMap<>();
            }
            PeerConnection old = devices.put(deviceId, connection);
            if (old != null) {
                try {
                    old.close();
                    logger.info("Replaced existing connection for user '{}' device '{}'", userId, deviceId);
                } catch (Exception e) {
                    logger.warn("Failed to close replaced connection for user '{}' device '{}'", userId, deviceId, e);
                }
            }
            return devices;
        });

        logger.info("Registered peer for user '{}' on device {}", userId, deviceId);
    }

    /**
     * Routes a message packet to the intended recipient device.
     *
     * @param packet   the packet to route
     * @param senderId the sender's user ID (for logging)
     */
    public void routeMessage(Packet packet, String senderId) {
        if (packet == null || packet.getRecipientId() == null) {
            logger.warn("Invalid packet or recipientId; message dropped.");
            return;
        }
        sendToPeer(packet, packet.getRecipientId(), packet.getRecipientDeviceId(), senderId);
    }

    /**
     * Routes a PreKey-related packet to the intended recipient device.
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
        sendToPeer(packet, recipientId, deviceId, null);
    }

    /**
     * Unregisters all devices for a given user and closes all associated connections.
     *
     * @param userId the user to unregister
     * @return true if any connections were unregistered, false otherwise
     */
    public boolean unregisterPeer(String userId) {
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
            return true;
        } else {
            logger.info("No active connections to unregister for '{}'", userId);
            return false;
        }
    }

    /**
     * Unregisters a specific device for a user.
     *
     * @param userId   the user ID
     * @param deviceId the device ID
     * @return true if device was unregistered, false otherwise
     */
    public boolean unregisterPeerDevice(String userId, int deviceId) {
        return activePeers.computeIfPresent(userId, (uid, devices) -> {
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
                return null; // removes user from activePeers
            }
            return devices;
        }) != null;
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

    /**
     * Helper method to send a packet to a specific peer connection.
     *
     * @param packet        the packet to send
     * @param recipientId   the recipient user ID
     * @param recipientDeviceId the recipient device ID
     * @param senderId      the sender user ID (optional, used for logging)
     */
    private void sendToPeer(Packet packet, String recipientId, int recipientDeviceId, String senderId) {
        PeerConnection recipientConn = getConnection(recipientId, recipientDeviceId);
        if (recipientConn != null) {
            try {
                recipientConn.sendMessageObject(packet);
                if (senderId != null) {
                    logger.debug("Routed message from '{}' to '{}@{}'", senderId, recipientId, recipientDeviceId);
                } else {
                    logger.debug("Routed packet to '{}@{}'", recipientId, recipientDeviceId);
                }
            } catch (Exception e) {
                logger.error("Failed to send message to '{}@{}'", recipientId, recipientDeviceId, e);
            }
        } else {
            logger.warn("No connection for recipient '{}@{}'; packet dropped.", recipientId, recipientDeviceId);
        }
    }
}
