package com.securechat.server;

/**
 * Listener interface for monitoring peer connection lifecycle events.
 *
 * <p>Implementations of this interface can be registered to receive callbacks
 * when peers connect or disconnect from the server.
 */
public interface ConnectionListener {

    /**
     * Called when a peer device successfully connects.
     *
     * @param userId   the ID of the user who owns the connected device
     * @param deviceId the ID of the device that has connected
     */
    void onPeerConnected(String userId, int deviceId);

    /**
     * Called when a peer device disconnects or is disconnected.
     *
     * @param userId   the ID of the user who owns the disconnected device
     * @param deviceId the ID of the device that has disconnected
     */
    void onPeerDisconnected(String userId, int deviceId);
}
