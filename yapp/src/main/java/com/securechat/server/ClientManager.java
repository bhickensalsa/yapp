package com.securechat.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.securechat.protocol.dto.PreKeyBundleDTO;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages the registration, retrieval, and removal of {@link PreKeyBundleDTO} objects
 * associated with users and their devices.
 * 
 * <p>This class serves as an in-memory store mapping user identifiers to device-specific
 * pre-key bundles, allowing secure session initiation in a multi-device end-to-end
 * encryption system such as one based on the Signal Protocol.
 *
 * <p>Thread-safe operations are supported via {@link ConcurrentHashMap}.
 * 
 * @author bhickensalsa
 * @version 0.1
 */
public class ClientManager {

    private static final Logger logger = LoggerFactory.getLogger(ClientManager.class);
    private static final String LOG_PREFIX = "[ClientManager]";

    // Map of userId -> deviceId -> PreKeyBundleDTO
    private final Map<String, Map<Integer, PreKeyBundleDTO>> peerBundles = new ConcurrentHashMap<>();

    /**
     * Registers or updates a {@link PreKeyBundleDTO} for a specific user's device.
     *
     * <p>If a bundle already exists for the given device, it will be overwritten.
     *
     * @param userId   the unique identifier for the user (non-null and non-empty)
     * @param deviceId the device ID (must be non-negative)
     * @param bundle   the {@link PreKeyBundleDTO} to associate with this user/device (non-null)
     * @throws IllegalArgumentException if any argument is invalid
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
     * Retrieves the {@link PreKeyBundleDTO} for a specific user and device.
     *
     * @param userId   the user ID (non-null and non-empty)
     * @param deviceId the device ID (non-negative)
     * @return the corresponding {@link PreKeyBundleDTO}, or {@code null} if not found
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
     * Removes the {@link PreKeyBundleDTO} entry for a given user and device.
     *
     * <p>If this is the last device associated with the user, the user will also
     * be removed from the internal map.
     *
     * @param userId   the user ID (non-null and non-empty)
     * @param deviceId the device ID (non-negative)
     * @return {@code true} if the bundle was successfully removed, {@code false} otherwise
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
            if (deviceMap.isEmpty()) {
                peerBundles.remove(userId);
                logger.info("{} Removed user '{}' from ClientManager as no more devices remain", LOG_PREFIX, userId);
            }
            return true;
        }
        return false;
    }

    /**
     * Removes all stored {@link PreKeyBundleDTO}s from all users and devices.
     */
    public void clearAll() {
        peerBundles.clear();
        logger.info("{} Cleared all PreKeyBundles", LOG_PREFIX);
    }
}
