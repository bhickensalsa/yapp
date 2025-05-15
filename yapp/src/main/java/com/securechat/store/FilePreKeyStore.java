package com.securechat.store;

import com.securechat.crypto.libsignal.PreKeyBundleDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.*;
import java.util.concurrent.ConcurrentHashMap;

public class FilePreKeyStore implements PreKeyStore {

    private static final Logger logger = LoggerFactory.getLogger(FilePreKeyStore.class);

    private final Path storageDir;
    private final ConcurrentHashMap<String, PreKeyBundleDTO> cache = new ConcurrentHashMap<>();

    public FilePreKeyStore(String dir) {
        this.storageDir = Paths.get(dir);
        try {
            if (!Files.exists(storageDir)) {
                Files.createDirectories(storageDir);
                logger.info("Created storage directory at {}", storageDir.toAbsolutePath());
            }
            loadAll();
        } catch (IOException e) {
            logger.error("Could not initialize pre-key store directory {}: {}", storageDir, e.getMessage(), e);
            throw new RuntimeException("Could not initialize pre-key store directory", e);
        }
    }

    private void loadAll() {
        try {
            Files.list(storageDir)
                .filter(p -> p.toString().endsWith(".json"))
                .forEach(path -> {
                    try {
                        String content = Files.readString(path);
                        PreKeyBundleDTO dto = PreKeyBundleDTO.fromJson(content);
                        String[] parts = path.getFileName().toString().replace(".json", "").split("_");
                        String userId = parts[0];
                        int deviceId = Integer.parseInt(parts[1]);
                        cache.put(key(userId, deviceId), dto);
                        logger.info("Loaded pre-key bundle from file: {}", path);
                    } catch (Exception e) {
                        logger.warn("Failed to load bundle from file {}: {}", path, e.getMessage());
                    }
                });
        } catch (IOException e) {
            logger.error("Failed to scan directory {}: {}", storageDir, e.getMessage(), e);
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
            logger.info("Persisted pre-key bundle for user '{}' device {}", userId, deviceId);
        } catch (IOException e) {
            logger.error("Failed to persist bundle for {}/{}: {}", userId, deviceId, e.getMessage(), e);
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
                logger.info("Deleted pre-key bundle file for user '{}' device {}", userId, deviceId);
            } catch (IOException e) {
                logger.warn("Failed to delete bundle file for {}/{}: {}", userId, deviceId, e.getMessage());
            }
            return true;
        }
        return false;
    }
}
