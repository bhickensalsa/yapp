package com.securechat.protocol;

public enum MessageType {
    CIPHERTEXT,    // Encrypted content
    HANDSHAKE,     // Initial handshake message
    KEY_BUNDLE,    // Carries keys inside a message
    ACK,           // Acknowledgment at message level
    ERROR,         // Error inside a message (not transport)
    PREKEY         // Used during prekey message exchange
}

