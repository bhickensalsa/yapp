package com.securechat.network;

import com.securechat.protocol.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages peer connections and routes messages between users' devices.
 *
 * <p>This class maintains a thread-safe mapping of active peer connections,
 * organized by user ID and device ID. It supports registering, unregistering,
 * and routing message packets to the appropriate device connection.
 * 
 * @author bhickensalsa
 * @version 0.1
 */
public class MessageRouter {

    private static final Logger logger = LoggerFactory.getLogger(MessageRouter.class);

    /**
     * Maps userId -> (deviceId -> PeerConnection)
     */
    private final Map<String, Map<Integer, PeerConnection>> activePeers = new ConcurrentHashMap<>();

    /**
     * Registers or replaces a peer connection for a specific user and device.
     * If an existing connection is replaced, it will be closed.
     *
     * @param userId     the user's unique identifier (non-null)
     * @param deviceId   the device ID (non-negative)
     * @param connection the PeerConnection instance to register (non-null)
     * @throws IllegalArgumentException if any parameter is invalid
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
     * Routes a message packet to the intended recipient device based on the
     * recipient ID and device ID contained within the packet.
     *
     * @param packet   the message packet to route (non-null)
     * @param senderId the sender's user ID (used for logging)
     */
    public void routeMessage(Packet packet, String senderId) {
        if (packet == null || packet.getRecipientId() == null) {
            logger.warn("Invalid packet or recipientId; message dropped.");
            return;
        }
        sendToPeer(packet, packet.getRecipientId(), packet.getRecipientDeviceId(), senderId);
    }

    /**
     * Routes a PreKey-related packet to a specific recipient device.
     * This is typically used for key exchange or session setup.
     *
     * @param packet      the packet containing the PreKey bundle (non-null)
     * @param recipientId the recipient user's ID (non-null)
     * @param deviceId    the recipient device ID
     */
    public void routePreKeyPacket(Packet packet, String recipientId, int deviceId) {
        if (packet == null || recipientId == null || packet.getPreKeyBundlePayload() == null) {
            logger.warn("Invalid PreKey packet or missing payload; dropped.");
            return;
        }
        sendToPeer(packet, recipientId, deviceId, null);
    }

    /**
     * Unregisters all device connections for the specified user and closes
     * all associated peer connections.
     *
     * @param userId the user ID to unregister (non-null)
     * @return true if any connections were found and unregistered; false if
     *         no connections were found for the user
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
     * Unregisters a specific device connection for the given user and closes
     * the associated peer connection. If the user has no remaining devices,
     * the user is removed from active peers.
     *
     * @param userId   the user ID (non-null)
     * @param deviceId the device ID to unregister
     * @return true if the device connection was found and unregistered; false otherwise
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
                return null; // Removes the user from activePeers map
            }
            return devices;
        }) != null;
    }

    /**
     * Retrieves the active peer connection for the specified user and device.
     *
     * @param userId   the user ID (non-null)
     * @param deviceId the device ID
     * @return the PeerConnection instance if present and active; otherwise null
     */
    private PeerConnection getConnection(String userId, int deviceId) {
        Map<Integer, PeerConnection> devices = activePeers.get(userId);
        return devices != null ? devices.get(deviceId) : null;
    }

    /**
     * Sends a packet to the specified recipient's peer connection if it exists.
     * Logs success or failure accordingly.
     *
     * @param packet            the packet to send (non-null)
     * @param recipientId       the recipient user ID (non-null)
     * @param recipientDeviceId the recipient device ID
     * @param senderId          the sender user ID (optional, may be null, used for logging)
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
