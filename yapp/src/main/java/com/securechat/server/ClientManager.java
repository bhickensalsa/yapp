package com.securechat.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ClientManager {

    private static final Logger logger = LoggerFactory.getLogger(ClientManager.class);
    private static final String LOG_PREFIX = "[ClientManager]";

    // Map userId to their serialized PreKeyBundle (or public key data)
    private final Map<String, byte[]> publicKeys = new ConcurrentHashMap<>();

    /**
     * Registers or updates the public key (or serialized PreKeyBundle) for a user.
     *
     * @param userId    Unique identifier for the user
     * @param publicKey Serialized public key or PreKeyBundle bytes
     */
    public void register(String userId, byte[] publicKey) {
        if (userId == null || publicKey == null || publicKey.length == 0) {
            logger.warn("{} Attempt to register invalid userId or publicKey. userId={}, publicKey length={}",
                    LOG_PREFIX, userId, (publicKey == null ? "null" : publicKey.length));
            throw new IllegalArgumentException("UserId and publicKey must be non-null and valid.");
        }
        publicKeys.put(userId, publicKey);
        logger.info("{} Registered public key for user '{}', key length: {}", LOG_PREFIX, userId, publicKey.length);
    }

    /**
     * Retrieves the public key (or serialized PreKeyBundle) for the given userId.
     *
     * @param userId Unique identifier for the user
     * @return The stored public key bytes or null if none exists
     */
    public byte[] getPublicKey(String userId) {
        if (userId == null) {
            logger.warn("{} Attempted to get public key for null userId", LOG_PREFIX);
            return null;
        }
        byte[] key = publicKeys.get(userId);
        if (key == null) {
            logger.debug("{} No public key found for user '{}'", LOG_PREFIX, userId);
        } else {
            logger.debug("{} Retrieved public key for user '{}', key length: {}", LOG_PREFIX, userId, key.length);
        }
        return key;
    }
}
