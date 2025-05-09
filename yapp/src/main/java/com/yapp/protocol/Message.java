package com.yapp.protocol;

public class Message {
    private final MessageType type;
    private final byte[] payload;

    public Message(MessageType type, byte[] payload) {
        this.type = type;
        this.payload = payload;
    }

    public MessageType getType() {
        return type;
    }

    public byte[] getPayload() {
        return payload;
    }
}
