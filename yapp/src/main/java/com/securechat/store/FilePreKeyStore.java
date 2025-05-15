package com.securechat.store;

import com.securechat.crypto.libsignal.PreKeyBundleDTO;

import java.io.IOException;
import java.nio.file.*;
import java.util.concurrent.ConcurrentHashMap;

public class FilePreKeyStore implements PreKeyStore {

    private final Path storageDir;
    private final ConcurrentHashMap<String, PreKeyBundleDTO> cache = new ConcurrentHashMap<>();

    public FilePreKeyStore(String dir) {
        this.storageDir = Paths.get(dir);
        try {
            if (!Files.exists(storageDir)) {
                Files.createDirectories(storageDir);
            }
            loadAll();
        } catch (IOException e) {
            throw new RuntimeException("Could not initialize pre-key store directory", e);
        }
    }

    private void loadAll() {
        try {
            Files.list(storageDir).filter(p -> p.toString().endsWith(".json")).forEach(path -> {
                try {
                    String content = Files.readString(path);
                    PreKeyBundleDTO dto = PreKeyBundleDTO.fromJson(content);
                    String[] parts = path.getFileName().toString().replace(".json", "").split("_");
                    String userId = parts[0];
                    int deviceId = Integer.parseInt(parts[1]);
                    cache.put(key(userId, deviceId), dto);
                } catch (Exception e) {
                    System.err.println("Failed to load bundle from file: " + path);
                }
            });
        } catch (IOException e) {
            System.err.println("Failed to scan directory: " + storageDir);
        }
    }

    private String key(String userId, int deviceId) {
        return userId + "_" + deviceId;
    }

    private Path path(String userId, int deviceId) {
        return storageDir.resolve(key(userId, deviceId) + ".json");
    }

    @Override
    public void registerPreKeyBundle(String userId, int deviceId, PreKeyBundleDTO bundle) {
        cache.put(key(userId, deviceId), bundle);
        try {
            Files.writeString(path(userId, deviceId), bundle.toJson(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (IOException e) {
            throw new RuntimeException("Failed to persist bundle for " + userId + "/" + deviceId, e);
        }
    }

    @Override
    public PreKeyBundleDTO getPreKeyBundle(String userId, int deviceId) {
        return cache.get(key(userId, deviceId));
    }

    @Override
    public boolean removePreKey(String userId, int deviceId, int preKeyId) {
        PreKeyBundleDTO dto = cache.get(key(userId, deviceId));
        if (dto != null && dto.preKeyId == preKeyId) {
            cache.remove(key(userId, deviceId));
            try {
                Files.deleteIfExists(path(userId, deviceId));
            } catch (IOException e) {
                System.err.println("Failed to delete bundle file for " + userId + "/" + deviceId);
            }
            return true;
        }
        return false;
    }
}
