package com.securechat.protocol;

import java.time.Instant;

public class Message {
    private String messageId;
    private String sender;
    private String recipient;
    private String messageType; // e.g. "TEXT", "FILE", "KEY_EXCHANGE"
    private String encryptedPayload; // base64 encoded ciphertext
    private long timestamp;

    public Message() {
        // For deserialization
    }

    public Message(String messageId, String sender, String recipient, String messageType, String encryptedPayload) {
        this.messageId = messageId;
        this.sender = sender;
        this.recipient = recipient;
        this.messageType = messageType;
        this.encryptedPayload = encryptedPayload;
        this.timestamp = Instant.now().toEpochMilli();
    }

    // Getters and setters
    public String getMessageId() { return messageId; }
    public void setMessageId(String messageId) { this.messageId = messageId; }

    public String getSender() { return sender; }
    public void setSender(String sender) { this.sender = sender; }

    public String getRecipient() { return recipient; }
    public void setRecipient(String recipient) { this.recipient = recipient; }

    public String getMessageType() { return messageType; }
    public void setMessageType(String messageType) { this.messageType = messageType; }

    public String getEncryptedPayload() { return encryptedPayload; }
    public void setEncryptedPayload(String encryptedPayload) { this.encryptedPayload = encryptedPayload; }

    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

    @Override
    public String toString() {
        return "Message{" +
               "id='" + messageId + '\'' +
               ", sender='" + sender + '\'' +
               ", recipient='" + recipient + '\'' +
               ", type='" + messageType + '\'' +
               ", encryptedPayload='" + encryptedPayload + '\'' +
               ", timestamp=" + timestamp +
               '}';
    }
}
