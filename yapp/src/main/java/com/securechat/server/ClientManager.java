package com.securechat.server;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ClientManager {

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
            throw new IllegalArgumentException("UserId and publicKey must be non-null and valid.");
        }
        publicKeys.put(userId, publicKey);
    }

    /**
     * Retrieves the public key (or serialized PreKeyBundle) for the given userId.
     *
     * @param userId Unique identifier for the user
     * @return The stored public key bytes or null if none exists
     */
    public byte[] getPublicKey(String userId) {
        if (userId == null) {
            return null;
        }
        return publicKeys.get(userId);
    }
}
