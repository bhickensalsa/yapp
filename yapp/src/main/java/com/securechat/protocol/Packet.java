package com.securechat.protocol;

import java.io.Serializable;
import com.securechat.crypto.libsignal.PreKeyBundleDTO;

public class Packet implements Serializable {
    private static final long serialVersionUID = 1L;

    private PacketType type;

    // Only one of these will be used depending on type
    private PreKeyBundleDTO preKeyBundlePayload;
    private byte[] messagePayload;
    private String stringPayload;  // for GET_PREKEY_BUNDLE requests

    private String senderId;
    private String recipientId;

    public Packet() {
        // For deserialization
    }

    // PREKEY_BUNDLE packet constructor
    public Packet(String recipientId, PreKeyBundleDTO preKeyBundle) {
        this.recipientId = recipientId;
        this.type = PacketType.PREKEY_BUNDLE;
        this.preKeyBundlePayload = preKeyBundle;
    }

    // GET_PREKEY_BUNDLE request constructor
    public Packet(String recipientId, PacketType type, String requestedUserId) {
        if (type != PacketType.GET_PREKEY_BUNDLE) {
            throw new IllegalArgumentException("Only for GET_PREKEY_BUNDLE type");
        }
        this.recipientId = recipientId;
        this.type = type;
        this.stringPayload = requestedUserId;
    }

    // MESSAGE packet constructor with encrypted byte[] payload
    public Packet(PacketType type, byte[] messagePayload, String senderId, String recipientId) {
        if (type != PacketType.MESSAGE && type != PacketType.PREKEY_MESSAGE) {
            throw new IllegalArgumentException("Only for PREKEY_MESSAGE and MESSAGE type");
        }
        this.type = type;
        this.messagePayload = messagePayload;
        this.senderId = senderId;
        this.recipientId = recipientId;
    }

    // Getters and setters

    public PacketType getType() {
        return type;
    }

    public void setType(PacketType type) {
        this.type = type;
    }

    public PreKeyBundleDTO getPreKeyBundlePayload() {
        return preKeyBundlePayload;
    }

    public void setPreKeyBundlePayload(PreKeyBundleDTO preKeyBundlePayload) {
        this.preKeyBundlePayload = preKeyBundlePayload;
    }

    public byte[] getMessagePayload() {
        return messagePayload;
    }

    public void setMessagePayload(byte[] messagePayload) {
        this.messagePayload = messagePayload;
    }

    public String getStringPayload() {
        return stringPayload;
    }

    public void setStringPayload(String stringPayload) {
        this.stringPayload = stringPayload;
    }

    public String getSenderId() {
        return senderId;
    }

    public void setSenderId(String senderId) {
        this.senderId = senderId;
    }

    public String getRecipientId() {
        return recipientId;
    }

    public void setRecipientId(String recipientId) {
        this.recipientId = recipientId;
    }

    public String getSender() {
        return senderId;
    }

    @Override
    public String toString() {
        return "Packet{" +
                "type=" + type +
                ", preKeyBundlePayload=" + preKeyBundlePayload +
                ", messagePayload=" + (messagePayload != null ? messagePayload.length + " bytes" : null) +
                ", stringPayload='" + stringPayload + '\'' +
                ", senderId='" + senderId + '\'' +
                ", recipientId='" + recipientId + '\'' +
                '}';
    }
}
