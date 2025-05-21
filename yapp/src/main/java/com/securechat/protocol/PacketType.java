package com.securechat.protocol;

/**
 * Enum representing the different types of packets used in the SecureChat protocol.
 * <p>
 * Each packet type corresponds to a specific function or message type in the
 * secure messaging workflow, such as exchanging encrypted messages, session
 * initiation via prekey bundles, acknowledgments, errors, or control commands.
 * </p>
 * 
 * @author bhickensalsa
 * @version 0.2
 */
public enum PacketType {

    /** 
     * Packet carrying a standard encrypted message.
     * Used for sending regular chat messages between peers.
     */
    MESSAGE,

    /**
     * Packet carrying a prekey message.
     * Used during session establishment to bootstrap encryption keys.
     */
    PREKEY_MESSAGE,

    /**
     * Packet carrying a PreKeyBundleDTO.
     * Used to share the sender's prekey bundle for key registration and session setup.
     */
    PREKEY_BUNDLE,

    /**
     * Packet requesting a prekey bundle from the server.
     * Typically sent by a client to retrieve another user's prekey bundle.
     */
    GET_PREKEY_BUNDLE,

    /**
     * Acknowledgement packet.
     * Sent to confirm receipt of a message or packet.
     */
    ACK,

    /**
     * Error packet indicating a failure or issue.
     * Used to communicate errors between peers or from server.
     */
    ERROR,

    /**
     * Command packet used for control or protocol commands.
     * Can be used to execute protocol-level commands or other control operations.
     */
    COMMAND,

    /**
     * Notification that a new user has connected.
     * Sent by the server to clients when a new user joins.
     */
    USER_CONNECTED,

    /**
     * Notification that a user has disconnected.
     * Sent by the server to clients when a user leaves.
     */
    USER_DISCONNECTED,

    /**
     * Packet containing the full list of currently connected users.
     * Typically sent to a newly connected client.
     */
    USER_LIST_UPDATE
}
