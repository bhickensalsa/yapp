package com.securechat.network;

/**
 * Listener interface for receiving decrypted messages from peers.
 *
 * <p>Implementations should handle the processing or display of
 * messages once they have been successfully decrypted.
 */
public interface DecryptedMessageListener {

    /**
     * Called when a decrypted message is received from a peer.
     *
     * @param fromUser   the sender's user ID
     * @param fromDevice the sender's device ID
     * @param message    the decrypted plaintext message content
     */
    void onDecryptedMessage(String fromUser, int fromDevice, String message);
}
