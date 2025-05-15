package com.securechat.store;

import com.securechat.crypto.libsignal.PreKeyBundleDTO;

public interface PreKeyStore {

    /**
     * Registers or updates a PreKeyBundle for the given userId and deviceId.
     */
    void registerPreKeyBundle(String userId, int deviceId, PreKeyBundleDTO bundle);

    /**
     * Retrieves the stored PreKeyBundleDTO for the given userId and deviceId.
     * Returns null if not found.
     */
    PreKeyBundleDTO getPreKeyBundle(String userId, int deviceId);

    /**
     * Optionally removes a one-time PreKey after use.
     */
    boolean removePreKey(String userId, int deviceId, int preKeyId);
}
