package com.securechat.client;

import com.securechat.crypto.libsignal.PreKeyBundleBuilder;
import com.securechat.crypto.libsignal.PreKeyBundleDTO;
import com.securechat.crypto.libsignal.SignalKeyStore;
import com.securechat.crypto.libsignal.SignalProtocolManager;
import com.securechat.network.PeerConnection;
import com.securechat.protocol.Message;
import com.securechat.protocol.MessageSerializer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.PreKeyBundle;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
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
    private ObjectInputStream in;
    private ObjectOutputStream out;

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

            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());

            PreKeyBundle myBundle = PreKeyBundleBuilder.build(
                keyStore.getLocalRegistrationId(),
                deviceId,
                keyStore,
                preKeyId,
                signedPreKeyId
            );
            String myBundleJson = PreKeyBundleDTO.fromPreKeyBundle(myBundle).toJson();

            out.writeObject(userId);
            out.writeObject(myBundleJson);
            out.flush();

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
            out.writeObject("GET_PREKEY_BUNDLE:" + peerId);
            out.flush();

            Object responseObj = in.readObject();
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
            byte[] ciphertext = cryptoManager.encryptMessage(recipientAddress, plaintext);
            String encoded = Base64.getEncoder().encodeToString(ciphertext);

            Message message = new Message(
                UUID.randomUUID().toString(),
                userId,
                recipientId,
                "TEXT",
                encoded
            );
            connection.send(MessageSerializer.serialize(message));
            logger.debug("Sent message from {} to {}", userId, recipientId);

        } catch (Exception e) {
            logger.error("Error sending message from {} to {}: {}", userId, recipientId, e.getMessage(), e);
        }
    }

    public void listen() {
        new Thread(() -> {
            try {
                while (true) {
                    String received = connection.receive();
                    if (received == null) break;

                    Message msg = MessageSerializer.deserialize(received);
                    if (msg == null) {
                        logger.warn("Received invalid message format, skipping");
                        continue;
                    }

                    SignalProtocolAddress senderAddress = new SignalProtocolAddress(msg.getSender(), deviceId);
                    byte[] ciphertext = Base64.getDecoder().decode(msg.getEncryptedPayload());
                    String plaintext = cryptoManager.decryptMessage(senderAddress, ciphertext);

                    logger.info("From {}: {}", msg.getSender(), plaintext);
                }
            } catch (Exception e) {
                logger.error("Error receiving message: {}", e.getMessage(), e);
            }
        }, "UserClient-Listener-" + userId).start();
    }

    public SignalProtocolManager getCryptoManager() {
        return cryptoManager;
    }

    public String getUserId() {
        return userId;
    }
}
