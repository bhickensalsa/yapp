package com.securechat.protocol;

import java.io.Serializable;
import com.securechat.crypto.libsignal.PreKeyBundleDTO;

public class Packet implements Serializable {
    private static final long serialVersionUID = 1L;

    private PacketType type;

    // Only one of these will be used depending on the packet type
    private PreKeyBundleDTO preKeyBundlePayload;
    private byte[] messagePayload;

    private String senderId;
    private int senderDeviceId;      // Device ID of the sender
    private String recipientId;
    private int recipientDeviceId;

    public Packet() {
        // For deserialization
    }

    // PREKEY_BUNDLE packet constructor — includes senderDeviceId
    public Packet(String senderId, int senderDeviceId, PreKeyBundleDTO preKeyBundle) {
        this.senderId = senderId;
        this.senderDeviceId = senderDeviceId;
        this.preKeyBundlePayload = preKeyBundle;
        this.type = PacketType.PREKEY_BUNDLE;
    }

    // GET_PREKEY_BUNDLE packet constructor — includes senderDeviceId
    public Packet(String senderId, int senderDeviceId, String recipientId, int recipientDeviceId) {
        this.senderId = senderId;
        this.senderDeviceId = senderDeviceId;
        this.recipientId = recipientId;
        this.recipientDeviceId = recipientDeviceId;
        this.type = PacketType.GET_PREKEY_BUNDLE;
    }

    // MESSAGE and PREKEY_MESSAGE packet constructor with encrypted payload and senderDeviceId
    public Packet(String senderId, int senderDeviceId, String recipientId, int recipientDeviceId, byte[] messagePayload, PacketType type) {
        if (type != PacketType.MESSAGE && type != PacketType.PREKEY_MESSAGE && type != PacketType.ACK) {
            throw new IllegalArgumentException("Only MESSAGE, ACK, and PREKEY_MESSAGE packet types allowed for this constructor");
        }
        this.senderId = senderId;
        this.senderDeviceId = senderDeviceId;
        this.recipientId = recipientId;
        this.recipientDeviceId = recipientDeviceId;
        this.messagePayload = messagePayload;
        this.type = type;
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

    public String getSenderId() {
        return senderId;
    }

    public void setSenderId(String senderId) {
        this.senderId = senderId;
    }

    public int getSenderDeviceId() {
        return senderDeviceId;
    }

    public void setSenderDeviceId(int senderDeviceId) {
        this.senderDeviceId = senderDeviceId;
    }

    public String getRecipientId() {
        return recipientId;
    }

    public void setRecipientId(String recipientId) {
        this.recipientId = recipientId;
    }

    public int getRecipientDeviceId() {
        return recipientDeviceId;
    }

    public void setRecipientDeviceId(int recipientDeviceId) {
        this.recipientDeviceId = recipientDeviceId;
    }

    @Override
    public String toString() {
        return "Packet{" +
                "type=" + type +
                ", preKeyBundlePayload=" + preKeyBundlePayload +
                ", messagePayload=" + (messagePayload != null ? messagePayload.length + " bytes" : null) +
                ", senderId='" + senderId + '\'' +
                ", senderDeviceId=" + senderDeviceId +
                ", recipientId='" + recipientId + '\'' +
                '}';
    }
}
