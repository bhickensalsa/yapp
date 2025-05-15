package com.securechat.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class ConfigLoader {
    private static final Logger logger = LoggerFactory.getLogger(ConfigLoader.class);
    private final Properties properties = new Properties();

    public ConfigLoader(String fileName) {
        try (InputStream input = getClass().getClassLoader().getResourceAsStream(fileName)) {
            if (input == null) {
                logger.error("Config file not found: {}", fileName);
                throw new RuntimeException("Config file not found: " + fileName);
            }
            properties.load(input);
            logger.info("Config file '{}' loaded successfully", fileName);
        } catch (IOException e) {
            logger.error("Error loading config file '{}': {}", fileName, e.getMessage(), e);
            throw new RuntimeException("Error loading config", e);
        }
    }

    public String get(String key) {
        String value = properties.getProperty(key);
        logger.debug("Config get: key='{}' value='{}'", key, value);
        return value;
    }

    public int getInt(String key, int defaultValue) {
        try {
            String value = properties.getProperty(key);
            int intValue = Integer.parseInt(value);
            logger.debug("Config getInt: key='{}' value={}", key, intValue);
            return intValue;
        } catch (Exception e) {
            logger.warn("Config getInt failed for key='{}', returning default value {}: {}", key, defaultValue, e.getMessage());
            return defaultValue;
        }
    }
}
