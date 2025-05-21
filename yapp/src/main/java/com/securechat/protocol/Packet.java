package com.securechat.protocol;

import java.io.Serializable;

import com.securechat.protocol.dto.PreKeyBundleDTO;

/**
 * Represents a communication packet used in the secure chat protocol.
 * <p>
 * A Packet can represent different types of messages exchanged between users,
 * including pre-key bundles, encrypted messages, acknowledgments, and control commands.
 * Depending on the {@link PacketType}, the payload and fields used will vary.
 * </p>
 *
 * <p>This class implements {@link Serializable} to allow easy transmission
 * over network streams.</p>
 * 
 * @author bhickensalsa
 * @version 0.2
 */
public class Packet implements Serializable {
    private static final long serialVersionUID = 1L;

    private PacketType type;

    // Payload fields - only one used depending on packet type
    private PreKeyBundleDTO preKeyBundlePayload;
    private byte[] messagePayload;

    private String senderId;
    private int senderDeviceId;      // Device ID of the sender
    private String recipientId;
    private int recipientDeviceId;

    /**
     * Default constructor for deserialization frameworks.
     */
    public Packet() {
        // For deserialization
    }

    /**
     * Constructs a PREKEY_BUNDLE packet containing a pre-key bundle payload.
     *
     * @param senderId       the unique ID of the sender
     * @param senderDeviceId the device ID of the sender
     * @param preKeyBundle   the pre-key bundle payload
     */
    public Packet(String senderId, int senderDeviceId, PreKeyBundleDTO preKeyBundle) {
        this.senderId = senderId;
        this.senderDeviceId = senderDeviceId;
        this.preKeyBundlePayload = preKeyBundle;
        this.type = PacketType.PREKEY_BUNDLE;
    }

    /**
     * Constructs a GET_PREKEY_BUNDLE packet, requesting a pre-key bundle
     * for a recipient's specific device.
     *
     * @param senderId        the unique ID of the sender (requester)
     * @param senderDeviceId  the device ID of the sender
     * @param recipientId     the recipient user ID whose pre-key bundle is requested
     * @param recipientDeviceId the recipient's device ID
     */
    public Packet(String senderId, int senderDeviceId, String recipientId, int recipientDeviceId) {
        this.senderId = senderId;
        this.senderDeviceId = senderDeviceId;
        this.recipientId = recipientId;
        this.recipientDeviceId = recipientDeviceId;
        this.type = PacketType.GET_PREKEY_BUNDLE;
    }

    /**
     * Constructs a packet for MESSAGE, PREKEY_MESSAGE, or ACK types
     * with an encrypted payload.
     *
     * @param senderId        the unique ID of the sender
     * @param senderDeviceId  the device ID of the sender
     * @param recipientId     the unique ID of the recipient
     * @param recipientDeviceId the device ID of the recipient
     * @param messagePayload  the encrypted message payload as bytes
     * @param type            the packet type; must be MESSAGE, PREKEY_MESSAGE, or ACK
     * @throws IllegalArgumentException if the packet type is not one of MESSAGE, PREKEY_MESSAGE, or ACK
     */
    public Packet(String senderId, int senderDeviceId, String recipientId, int recipientDeviceId, byte[] messagePayload, PacketType type) {
        if (type != PacketType.MESSAGE &&
            type != PacketType.PREKEY_MESSAGE &&
            type != PacketType.ACK &&
            type != PacketType.USER_CONNECTED &&
            type != PacketType.USER_DISCONNECTED) {
            throw new IllegalArgumentException("Unsupported packet type for message payload");
        }
        this.senderId = senderId;
        this.senderDeviceId = senderDeviceId;
        this.recipientId = recipientId;
        this.recipientDeviceId = recipientDeviceId;
        this.messagePayload = messagePayload;
        this.type = type;
    }

    /**
     * Returns the type of this packet.
     *
     * @return the packet type
     */
    public PacketType getType() {
        return type;
    }

    /**
     * Sets the packet type.
     *
     * @param type the packet type to set
     */
    public void setType(PacketType type) {
        this.type = type;
    }

    /**
     * Returns the pre-key bundle payload if this packet is of type PREKEY_BUNDLE.
     *
     * @return the pre-key bundle payload, or null if not applicable
     */
    public PreKeyBundleDTO getPreKeyBundlePayload() {
        return preKeyBundlePayload;
    }

    /**
     * Sets the pre-key bundle payload.
     *
     * @param preKeyBundlePayload the pre-key bundle payload to set
     */
    public void setPreKeyBundlePayload(PreKeyBundleDTO preKeyBundlePayload) {
        this.preKeyBundlePayload = preKeyBundlePayload;
    }

    /**
     * Returns the encrypted message payload.
     *
     * @return the message payload as a byte array, or null if not applicable
     */
    public byte[] getMessagePayload() {
        return messagePayload;
    }

    /**
     * Sets the encrypted message payload.
     *
     * @param messagePayload the message payload to set
     */
    public void setMessagePayload(byte[] messagePayload) {
        this.messagePayload = messagePayload;
    }

    /**
     * Returns the sender's user ID.
     *
     * @return the sender ID
     */
    public String getSenderId() {
        return senderId;
    }

    /**
     * Sets the sender's user ID.
     *
     * @param senderId the sender ID to set
     */
    public void setSenderId(String senderId) {
        this.senderId = senderId;
    }

    /**
     * Returns the sender's device ID.
     *
     * @return the sender device ID
     */
    public int getSenderDeviceId() {
        return senderDeviceId;
    }

    /**
     * Sets the sender's device ID.
     *
     * @param senderDeviceId the sender device ID to set
     */
    public void setSenderDeviceId(int senderDeviceId) {
        this.senderDeviceId = senderDeviceId;
    }

    /**
     * Returns the recipient's user ID.
     *
     * @return the recipient ID
     */
    public String getRecipientId() {
        return recipientId;
    }

    /**
     * Sets the recipient's user ID.
     *
     * @param recipientId the recipient ID to set
     */
    public void setRecipientId(String recipientId) {
        this.recipientId = recipientId;
    }

    /**
     * Returns the recipient's device ID.
     *
     * @return the recipient device ID
     */
    public int getRecipientDeviceId() {
        return recipientDeviceId;
    }

    /**
     * Sets the recipient's device ID.
     *
     * @param recipientDeviceId the recipient device ID to set
     */
    public void setRecipientDeviceId(int recipientDeviceId) {
        this.recipientDeviceId = recipientDeviceId;
    }

    /**
     * Returns a string representation of the packet for debugging.
     *
     * @return string describing the packet
     */
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
