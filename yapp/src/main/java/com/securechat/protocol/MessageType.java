package com.securechat.protocol;

public enum MessageType {
    CIPHERTEXT,
    HANDSHAKE,
    KEY_BUNDLE,
    ACK,
    ERROR,
    PREKEY
}
