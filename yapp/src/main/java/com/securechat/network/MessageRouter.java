package com.securechat.network;

import com.securechat.protocol.Packet;
import com.securechat.server.ConnectionListener;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages active peer connections and routes messages between users' devices in SecureChat.
 *
 * <p>This class maintains a thread-safe mapping of connected peers, organized by user ID and device ID.
 * It supports registering and unregistering peer connections, routing message packets to the correct
 * device connection, and notifying a connection listener about lifecycle events.
 *
 * <p>Designed for concurrent usage by multiple threads handling network I/O.
 *
 * @author bhickensalsa
 * @version 0.2
 */
public class MessageRouter {

    private static final Logger logger = LoggerFactory.getLogger(MessageRouter.class);

    /**
     * Mapping of user IDs to device ID -> PeerConnection mappings.
     * This structure supports multiple devices per user.
     */
    private final Map<String, Map<Integer, PeerConnection>> activePeers = new ConcurrentHashMap<>();

    /**
     * Optional listener to receive callbacks on peer connection and disconnection events.
     */
    private ConnectionListener connectionListener;

    /**
     * Sets the listener for connection lifecycle events.
     *
     * @param listener the listener to notify on peer connection changes
     */
    public void setConnectionListener(ConnectionListener listener) {
        this.connectionListener = listener;
    }

    /**
     * Returns the set of device IDs currently connected for a given user.
     *
     * @param userId the user ID to query
     * @return a set of connected device IDs; empty if none connected or user unknown
     */
    public Set<Integer> getConnectedDeviceIds(String userId) {
        Map<Integer, PeerConnection> userPeers = activePeers.get(userId);
        if (userPeers == null) return Collections.emptySet();
        return userPeers.keySet();
    }

    /**
     * Registers a new peer connection for the specified user and device.
     * If a connection already exists for that device, it is closed and replaced.
     *
     * @param userId     the user ID owning the device
     * @param deviceId   the device ID of the connection
     * @param connection the peer connection instance
     * @throws IllegalArgumentException if userId is null, deviceId is negative, or connection is null
     */
    public void registerPeer(String userId, int deviceId, PeerConnection connection) {
        if (userId == null || connection == null || deviceId < 0) {
            logger.warn("Invalid parameters for registering peer: userId={}, deviceId={}", userId, deviceId);
            throw new IllegalArgumentException("Invalid parameters for registerPeer");
        }

        // Insert or update the device connection for the user atomically
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

        // Notify listener about new connection
        if (connectionListener != null) {
            connectionListener.onPeerConnected(userId, deviceId);
        }
    }

    /**
     * Routes an incoming message packet to the recipient's device connection.
     * If no connection exists, the packet is dropped.
     *
     * @param packet   the packet containing the message
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
     * Routes an incoming PreKey packet to the specified recipient device.
     * If no connection exists or the packet payload is missing, the packet is dropped.
     *
     * @param packet      the PreKey packet containing cryptographic handshake info
     * @param recipientId the recipient user ID
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
     * Unregisters all device connections for a given user,
     * closing each connection and notifying the listener.
     *
     * @param userId the user ID whose connections are to be removed
     * @return true if any connections were removed, false otherwise
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
                if (connectionListener != null) {
                    connectionListener.onPeerDisconnected(userId, deviceId);
                }
            });
            return true;
        } else {
            logger.info("No active connections to unregister for '{}'", userId);
            return false;
        }
    }

    /**
     * Unregisters a single device connection for a user.
     * Closes the connection and notifies the listener.
     *
     * @param userId   the user ID owning the device
     * @param deviceId the device ID to unregister
     * @return true if the device was found and unregistered, false otherwise
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
                if (connectionListener != null) {
                    connectionListener.onPeerDisconnected(userId, deviceId);
                }
            }
            // Remove user from map if no devices left
            return devices.isEmpty() ? null : devices;
        }) != null;
    }

    /**
     * Retrieves the connection object for a specific user device.
     *
     * @param userId   the user ID
     * @param deviceId the device ID
     * @return the PeerConnection if found, or null if no connection exists
     */
    private PeerConnection getConnection(String userId, int deviceId) {
        Map<Integer, PeerConnection> devices = activePeers.get(userId);
        return devices != null ? devices.get(deviceId) : null;
    }

    /**
     * Sends a packet to the specified recipient device if a connection exists.
     * Logs success or failure accordingly.
     *
     * @param packet             the packet to send
     * @param recipientId        the recipient's user ID
     * @param recipientDeviceId  the recipient's device ID
     * @param senderId           the sender's user ID, can be null
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
