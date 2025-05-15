package com.securechat.store;

import com.securechat.crypto.libsignal.PreKeyBundleDTO;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryPreKeyStore implements PreKeyStore {

    // Nested map: userId → deviceId → PreKeyBundleDTO
    private final Map<String, Map<Integer, PreKeyBundleDTO>> store = new ConcurrentHashMap<>();

    @Override
    public void registerPreKeyBundle(String userId, int deviceId, PreKeyBundleDTO bundle) {
        store.computeIfAbsent(userId, k -> new ConcurrentHashMap<>()).put(deviceId, bundle);
    }

    @Override
    public PreKeyBundleDTO getPreKeyBundle(String userId, int deviceId) {
        Map<Integer, PreKeyBundleDTO> deviceMap = store.get(userId);
        if (deviceMap == null) return null;
        return deviceMap.get(deviceId);
    }

    @Override
    public boolean removePreKey(String userId, int deviceId, int preKeyId) {
        Map<Integer, PreKeyBundleDTO> deviceMap = store.get(userId);
        if (deviceMap == null) return false;

        PreKeyBundleDTO existing = deviceMap.get(deviceId);
        if (existing == null || existing.preKeyId != preKeyId) return false;

        deviceMap.remove(deviceId);
        return true;
    }
}
