package com.securechat.client;

import com.securechat.crypto.libsignal.PreKeyBundleBuilder;
import com.securechat.crypto.libsignal.PreKeyBundleDTO;
import com.securechat.crypto.libsignal.SignalKeyStore;
import com.securechat.crypto.libsignal.SignalProtocolManager;
import com.securechat.network.PeerConnection;
import com.securechat.protocol.Message;
import com.securechat.protocol.MessageSerializer;

import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.PreKeyBundle;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.Base64;
import java.util.UUID;

public class UserClient {

    private final String userId;
    private final int deviceId = 1;
    private final SignalKeyStore keyStore;
    private final SignalProtocolManager cryptoManager;
    private PeerConnection connection;
    private ObjectInputStream in;
    private ObjectOutputStream out;

    private final int preKeyId;
    private final int signedPreKeyId;

    // Constructor updated to accept preKey IDs (pass them from Launcher)
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

            // Use explicit preKeyId and signedPreKeyId here
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

            System.out.println("Registered prekey bundle with server as user " + userId);
        } catch (Exception e) {
            System.err.println("Failed to connect/register with server: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Request peer's PreKeyBundle from the server and establish session.
     */
    public boolean establishSessionWith(String peerId) {
        try {
            // Request peer's PreKeyBundle JSON from server
            out.writeObject("GET_PREKEY_BUNDLE:" + peerId);
            out.flush();

            Object responseObj = in.readObject();
            if (!(responseObj instanceof String)) {
                System.err.println("Unexpected response from server");
                return false;
            }

            String response = (String) responseObj;
            if (response.startsWith("PREKEY_BUNDLE:")) {
                String peerBundleJson = response.substring("PREKEY_BUNDLE:".length());
                PreKeyBundle peerBundle = PreKeyBundleDTO.fromJson(peerBundleJson).toPreKeyBundle();

                SignalProtocolAddress peerAddress = new SignalProtocolAddress(peerId, deviceId);
                cryptoManager.initializeSession(peerAddress, peerBundle);

                System.out.println("Secure session established with " + peerId);
                return true;
            } else if (response.startsWith("ERROR:")) {
                System.err.println("Server error: " + response);
            } else {
                System.err.println("Unexpected server response: " + response);
            }
        } catch (Exception e) {
            System.err.println("Failed to establish session with " + peerId + ": " + e.getMessage());
            e.printStackTrace();
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

        } catch (Exception e) {
            System.err.println("Error sending message: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public void listen() {
        new Thread(() -> {
            try {
                while (true) {
                    String received = connection.receive();
                    if (received == null) break;

                    Message msg = MessageSerializer.deserialize(received);
                    if (msg == null) continue;

                    SignalProtocolAddress senderAddress = new SignalProtocolAddress(msg.getSender(), deviceId);
                    byte[] ciphertext = Base64.getDecoder().decode(msg.getEncryptedPayload());
                    String plaintext = cryptoManager.decryptMessage(senderAddress, ciphertext);

                    System.out.println("From " + msg.getSender() + ": " + plaintext);
                }
            } catch (Exception e) {
                System.err.println("Error receiving message: " + e.getMessage());
                e.printStackTrace();
            }
        }).start();
    }

    public SignalProtocolManager getCryptoManager() {
        return cryptoManager;
    }

    public String getUserId() {
        return userId;
    }
}
