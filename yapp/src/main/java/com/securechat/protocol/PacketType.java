package com.securechat.protocol;

public enum PacketType {
    MESSAGE,              // Packet carries a Message object
    PREKEY_BUNDLE,        // Packet carries a PreKeyBundleDTO
    GET_PREKEY_BUNDLE,    // Packet requests a prekey
    ACK, ERROR, COMMAND
}
