package com.securechat.protocol;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for serializing and deserializing Message objects.
 */
public class MessageSerializer {
    private static final Gson gson = new Gson();
    private static final Logger logger = LoggerFactory.getLogger(MessageSerializer.class);

    /**
     * Deserialize a JSON string into a Message object.
     *
     * @param json the JSON string
     * @return the parsed Message object, or null if parsing fails
     */
    public static Message deserialize(String json) {
        try {
            return gson.fromJson(json, Message.class);
        } catch (JsonSyntaxException e) {
            logger.error("[MessageSerializer] Failed to parse message JSON: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Serialize a Message object into its JSON representation.
     *
     * @param message the Message object
     * @return the JSON string
     */
    public static String serialize(Message message) {
        return gson.toJson(message);
    }
}
