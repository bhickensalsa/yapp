package com.securechat.protocol;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

/**
 * Utility class for serializing and deserializing Message objects.
 */
public class MessageSerializer {
    private static final Gson gson = new Gson();

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
            System.err.println("[MessageSerializer] Failed to parse message JSON: " + e.getMessage());
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
