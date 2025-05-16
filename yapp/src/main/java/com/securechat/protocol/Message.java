package com.securechat.protocol;

import java.io.Serializable;
import java.time.Instant;

/**
 * Represents an encrypted message sent between users over the network.
 */
public class Message implements Serializable {
    private static final long serialVersionUID = 1L;

    private String messageId;
    private String sender;
    private String recipient;
    private String encryptedPayload; // Base64 encoded ciphertext
    private MessageType messageType; // e.g., TEXT, FILE, KEY_EXCHANGE
    private long timestamp;
    private boolean isPreKeyMessage; // Indicates whether this message is a pre-key message

    public Message() {
        // Default constructor for deserialization
    }

    public Message(String messageId, String sender, String recipient, MessageType messageType, String encryptedPayload, boolean isPreKeyMessage) {
        this.messageId = messageId;
        this.sender = sender;
        this.recipient = recipient;
        this.messageType = messageType;
        this.encryptedPayload = encryptedPayload;
        this.timestamp = Instant.now().toEpochMilli();
        this.isPreKeyMessage = isPreKeyMessage;
    }

    // Getters and setters

    public String getMessageId() {
        return messageId;
    }

    public void setMessageId(String messageId) {
        this.messageId = messageId;
    }

    public String getSender() {
        return sender;
    }

    public void setSender(String sender) {
        this.sender = sender;
    }

    public String getRecipient() {
        return recipient;
    }

    public void setRecipient(String recipient) {
        this.recipient = recipient;
    }

    public MessageType getMessageType() {
        return messageType;
    }

    public void setMessageType(MessageType messageType) {
        this.messageType = messageType;
    }

    public String getEncryptedPayload() {
        return encryptedPayload;
    }

    public void setEncryptedPayload(String encryptedPayload) {
        this.encryptedPayload = encryptedPayload;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public boolean isPreKeyMessage() {
        return isPreKeyMessage;
    }

    public void setPreKeyMessage(boolean preKeyMessage) {
        isPreKeyMessage = preKeyMessage;
    }

    @Override
    public String toString() {
        return "Message{" +
               "id='" + messageId + '\'' +
               ", sender='" + sender + '\'' +
               ", recipient='" + recipient + '\'' +
               ", type=" + messageType +
               ", isPreKeyMessage=" + isPreKeyMessage +
               ", encryptedPayload='" + encryptedPayload + '\'' +
               ", timestamp=" + timestamp +
               '}';
    }
}
