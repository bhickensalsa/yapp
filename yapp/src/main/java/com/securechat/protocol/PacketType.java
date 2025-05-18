package com.securechat.protocol;

/**
 * Defines types of packets used in the SecureChat protocol.
 */
public enum PacketType {
    /** Packet carrying a standard encrypted message */
    MESSAGE,

    /** Packet carrying a prekey message (used in session establishment) */
    PREKEY_MESSAGE,

    /** Packet carrying a PreKeyBundleDTO for key registration */
    PREKEY_BUNDLE,

    /** Packet requesting a prekey bundle from the server */
    GET_PREKEY_BUNDLE,

    /** Acknowledgement packet */
    ACK,

    /** Error packet indicating failure or issue */
    ERROR,

    /** Command packet used for control or protocol commands */
    COMMAND
}
