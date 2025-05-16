package com.securechat.protocol;

import java.io.Serializable;

/**
 * Packet is a wrapper object used to transmit various types of payloads between client and server.
 * It can contain messages, key bundles, control commands, etc.
 */
public class Packet implements Serializable {
    private static final long serialVersionUID = 1L;

    private PacketType type;
    private Object payload;

    public Packet() {
        // For deserialization
    }

    public Packet(PacketType type, Object payload) {
        this.type = type;
        this.payload = payload;
    }

    public PacketType getType() {
        return type;
    }

    public void setType(PacketType type) {
        this.type = type;
    }

    public Object getPayload() {
        return payload;
    }

    public void setPayload(Object payload) {
        this.payload = payload;
    }

    @Override
    public String toString() {
        return "Packet{" +
               "type=" + type +
               ", payload=" + payload +
               '}';
    }
}
