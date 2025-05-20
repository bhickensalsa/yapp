package com.securechat.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Loads configuration properties from a specified properties file located
 * in the classpath.
 *
 * <p>The properties file is loaded once during construction, and values
 * can be retrieved via key lookup methods. Supports retrieval as strings
 * or integers with default values.
 * 
 * @author bhickensalsa
 * @version 0.1
 */
public class ConfigLoader {
    private static final Logger logger = LoggerFactory.getLogger(ConfigLoader.class);
    private final Properties properties = new Properties();

    /**
     * Constructs a ConfigLoader and loads the properties from the given file name.
     *
     * @param fileName The name of the properties file to load from the classpath.
     * @throws RuntimeException if the file is not found or cannot be loaded.
     */
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

    /**
     * Retrieves the value associated with the specified key as a String.
     *
     * @param key The configuration key to lookup.
     * @return The value as a String, or {@code null} if the key does not exist.
     */
    public String get(String key) {
        String value = properties.getProperty(key);
        logger.debug("Config get: key='{}' value='{}'", key, value);
        return value;
    }

    /**
     * Retrieves the value associated with the specified key as an integer.
     * If the key does not exist or the value is not a valid integer, the
     * provided default value is returned.
     *
     * @param key The configuration key to lookup.
     * @param defaultValue The default integer value to return if lookup fails.
     * @return The integer value for the key, or {@code defaultValue} if not found or invalid.
     */
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
