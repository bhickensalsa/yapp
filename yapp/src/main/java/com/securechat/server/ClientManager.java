package com.securechat.server;

import com.securechat.crypto.libsignal.PreKeyBundleDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ClientManager {

    private static final Logger logger = LoggerFactory.getLogger(ClientManager.class);
    private static final String LOG_PREFIX = "[ClientManager]";

    // Map of userId -> deviceId -> PreKeyBundleDTO
    private final Map<String, Map<Integer, PreKeyBundleDTO>> peerBundles = new ConcurrentHashMap<>();

    /**
     * Registers or updates the PreKeyBundle for a user's device.
     *
     * @param userId Unique identifier for the user
     * @param deviceId Device ID of the user's device
     * @param bundle PreKeyBundleDTO associated with this device
     */
    public void register(String userId, int deviceId, PreKeyBundleDTO bundle) {
        if (userId == null || userId.isEmpty()) {
            throw new IllegalArgumentException("userId must be non-null and non-empty");
        }
        if (deviceId < 0) {
            throw new IllegalArgumentException("deviceId must be non-negative");
        }
        if (bundle == null) {
            throw new IllegalArgumentException("PreKeyBundleDTO must not be null");
        }

        peerBundles.computeIfAbsent(userId, k -> new ConcurrentHashMap<>()).put(deviceId, bundle);
        logger.info("{} Registered PreKeyBundle for user '{}' device '{}'", LOG_PREFIX, userId, deviceId);
    }

    /**
     * Retrieves the PreKeyBundleDTO for the specified user and device.
     *
     * @param userId User ID
     * @param deviceId Device ID
     * @return The PreKeyBundleDTO or null if not found
     */
    public PreKeyBundleDTO getPreKeyBundle(String userId, int deviceId) {
        if (userId == null || userId.isEmpty() || deviceId < 0) {
            logger.warn("{} Invalid parameters for getPreKeyBundle: userId='{}', deviceId={}", LOG_PREFIX, userId, deviceId);
            return null;
        }
        Map<Integer, PreKeyBundleDTO> deviceMap = peerBundles.get(userId);
        if (deviceMap == null) {
            logger.debug("{} No devices found for user '{}'", LOG_PREFIX, userId);
            return null;
        }
        PreKeyBundleDTO bundle = deviceMap.get(deviceId);
        if (bundle == null) {
            logger.debug("{} No PreKeyBundle found for user '{}' device '{}'", LOG_PREFIX, userId, deviceId);
        } else {
            logger.debug("{} Retrieved PreKeyBundle for user '{}' device '{}'", LOG_PREFIX, userId, deviceId);
        }
        return bundle;
    }

    /**
     * Removes the PreKeyBundle entry for a given user and device.
     *
     * @param userId User ID
     * @param deviceId Device ID
     * @return true if removed successfully, false otherwise
     */
    public boolean removePreKeyBundle(String userId, int deviceId) {
        if (userId == null || userId.isEmpty() || deviceId < 0) {
            logger.warn("{} Invalid parameters for removePreKeyBundle: userId='{}', deviceId={}", LOG_PREFIX, userId, deviceId);
            return false;
        }
        Map<Integer, PreKeyBundleDTO> deviceMap = peerBundles.get(userId);
        if (deviceMap == null) {
            return false;
        }
        PreKeyBundleDTO removed = deviceMap.remove(deviceId);
        if (removed != null) {
            logger.info("{} Removed PreKeyBundle for user '{}' device '{}'", LOG_PREFIX, userId, deviceId);
            // If no more devices for this user, remove the user key as well
            if (deviceMap.isEmpty()) {
                peerBundles.remove(userId);
                logger.info("{} Removed user '{}' from ClientManager as no more devices remain", LOG_PREFIX, userId);
            }
            return true;
        }
        return false;
    }

    /**
     * Clears all stored PreKeyBundles for all users.
     */
    public void clearAll() {
        peerBundles.clear();
        logger.info("{} Cleared all PreKeyBundles", LOG_PREFIX);
    }
}
