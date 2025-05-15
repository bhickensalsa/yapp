package com.securechat.client;

import com.securechat.crypto.libsignal.EncryptedMessageResult;
import com.securechat.crypto.libsignal.PreKeyBundleBuilder;
import com.securechat.crypto.libsignal.PreKeyBundleDTO;
import com.securechat.crypto.libsignal.SignalKeyStore;
import com.securechat.crypto.libsignal.SignalProtocolManager;
import com.securechat.network.PeerConnection;
import com.securechat.protocol.Message;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.PreKeyBundle;

import java.net.Socket;
import java.util.Base64;
import java.util.UUID;

public class UserClient {

    private static final Logger logger = LoggerFactory.getLogger(UserClient.class);
    

    private final String userId;
    private final int deviceId = 1;
    private final SignalKeyStore keyStore;
    private final SignalProtocolManager cryptoManager;
    private PeerConnection connection;

    private final int preKeyId;
    private final int signedPreKeyId;

    public UserClient(String userId, SignalKeyStore keyStore, int preKeyId, int signedPreKeyId) {
        this.userId = userId;
        this.keyStore = keyStore;
        this.cryptoManager = new SignalProtocolManager(keyStore);
        this.preKeyId = preKeyId;
        this.signedPreKeyId = signedPreKeyId;
    }

    /**
     * Connects to the server and registers this client's PreKeyBundle.
     */
    public void connectToServer(String host, int port) {
        try {
            Socket socket = new Socket(host, port);
            this.connection = new PeerConnection(socket);

            PreKeyBundle myBundle = PreKeyBundleBuilder.build(
                keyStore.getLocalRegistrationId(),
                deviceId,
                keyStore,
                preKeyId,
                signedPreKeyId
            );
            String myBundleJson = PreKeyBundleDTO.fromPreKeyBundle(myBundle).toJson();

            connection.sendObject(userId);
            connection.sendObject(myBundleJson);

            logger.info("Registered prekey bundle with server as user {}", userId);
        } catch (Exception e) {
            logger.error("Failed to connect/register with server: {}", e.getMessage(), e);
        }
    }

    /**
     * Request peer's PreKeyBundle from the server and establish session.
     */
    public boolean establishSessionWith(String peerId) {
        try {
            connection.sendObject("GET_PREKEY_BUNDLE:" + peerId);

            Object responseObj = connection.receiveObject();
            if (!(responseObj instanceof String)) {
                logger.warn("Unexpected response type from server for peer {}: {}", peerId, responseObj.getClass());
                return false;
            }

            String response = (String) responseObj;
            if (response.startsWith("PREKEY_BUNDLE:")) {
                String peerBundleJson = response.substring("PREKEY_BUNDLE:".length());
                PreKeyBundle peerBundle = PreKeyBundleDTO.fromJson(peerBundleJson).toPreKeyBundle();

                SignalProtocolAddress peerAddress = new SignalProtocolAddress(peerId, deviceId);
                cryptoManager.initializeSession(peerAddress, peerBundle);

                logger.info("Secure session established with {}", peerId);
                return true;
            } else if (response.startsWith("ERROR:")) {
                logger.error("Server error while requesting prekey bundle for {}: {}", peerId, response);
            } else {
                logger.warn("Unexpected server response while requesting prekey bundle for {}: {}", peerId, response);
            }
        } catch (Exception e) {
            logger.error("Failed to establish session with {}: {}", peerId, e.getMessage(), e);
        }
        return false;
    }

    public void sendMessage(String recipientId, String plaintext) {
        try {
            SignalProtocolAddress recipientAddress = new SignalProtocolAddress(recipientId, deviceId);

            boolean hasSession = keyStore.containsSession(recipientAddress); // You need to expose this method
            
            logger.debug("Checking if session exists for recipient address: {}", recipientAddress);
            logger.debug("Session exists: {}", hasSession);
            
            boolean isPreKey;
            byte[] ciphertext;

            if (!hasSession) {
                ciphertext = cryptoManager.encryptPreKeyMessage(recipientAddress, plaintext);
                isPreKey = true;
            } else {
                EncryptedMessageResult encrypted = cryptoManager.encryptMessage(recipientAddress, plaintext);
                if (encrypted == null || encrypted.ciphertext() == null) {
                    logger.error("Encryption failed for recipient {}", recipientId);
                    return;
                }
                ciphertext = encrypted.ciphertext();
                isPreKey = false; // Since session exists, this should never be a prekey message
            }
            logger.debug("isPreKey: " + isPreKey);

            String encoded = Base64.getEncoder().encodeToString(ciphertext);

            // String messageType = isPreKey ? "PREKEY" : "CIPHERTEXT";
            String messageType = isPreKey ? "CIPHERTEXT" : "PREKEY";

            logger.info("Sending message to '{}': type={}, plaintext='{}', ciphertext length={} bytes, base64 length={}",
                recipientId,
                messageType,
                plaintext.length() > 100 ? plaintext.substring(0, 100) + "..." : plaintext,
                ciphertext.length,
                encoded.length()
            );

            Message message = new Message(UUID.randomUUID().toString(), userId, recipientId, messageType, encoded);
            connection.sendObject(message);

            logger.info("Message sent successfully from {} to {}", userId, recipientId);

        } catch (Exception e) {
            logger.error("Error sending message from {} to {}: {}", userId, recipientId, e.getMessage(), e);
        }
    }

    public void listen() {
        new Thread(() -> {
            try {
                while (true) {
                    Object obj = connection.receiveObject();
                    if (obj == null) break;

                    if (!(obj instanceof Message)) {
                        logger.warn("Received unknown object: {}", obj.getClass());
                        continue;
                    }

                    Message msg = (Message) obj;
                    logger.debug("Received message ID: {} from sender: {}", msg.getMessageId(), msg.getSender());
                    logger.debug("Message type: {}", msg.getMessageType());
                    logger.debug("Base64 ciphertext length: {}", msg.getEncryptedPayload().length());
                    logger.trace("Base64 ciphertext (first 100 chars): {}",
                            msg.getEncryptedPayload().length() > 100
                                    ? msg.getEncryptedPayload().substring(0, 100) + "..."
                                    : msg.getEncryptedPayload());

                    SignalProtocolAddress senderAddress = new SignalProtocolAddress(msg.getSender(), deviceId);

                    byte[] ciphertext = Base64.getDecoder().decode(msg.getEncryptedPayload());
                    logger.debug("Decoded ciphertext length: {} bytes", ciphertext.length);

                    String plaintext = null;
                    try {
                        switch (msg.getMessageType()) {
                            case "PREKEY":
                                plaintext = cryptoManager.decryptPreKeyMessage(senderAddress, ciphertext);
                                break;
                            case "CIPHERTEXT":
                                plaintext = cryptoManager.decryptMessage(senderAddress, ciphertext);
                                break;
                            default:
                                logger.warn("Unsupported message type '{}'. Skipping message ID: {}", msg.getMessageType(), msg.getMessageId());
                        }
                    } catch (Exception e) {
                        logger.error("Exception during decryption of message ID {}: {}", msg.getMessageId(), e.getMessage(), e);
                    }

                    if (plaintext == null) {
                        logger.warn("Decryption failed or returned null for message ID: {}", msg.getMessageId());
                    } else {
                        logger.info("From {}: {}", msg.getSender(), plaintext);
                    }
                }
            } catch (Exception e) {
                logger.error("Error receiving message: {}", e.getMessage(), e);
            }
        }, "UserClient-Listener-" + userId).start();
    }
}
