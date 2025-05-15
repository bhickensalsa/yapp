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

    public UserClient(String userId, SignalKeyStore keyStore) {
        this.userId = userId;
        this.keyStore = keyStore;
        this.cryptoManager = new SignalProtocolManager(keyStore);
    }

    public void connectToPeer(String host, int port, boolean isInitiator) {
        try {
            Socket socket = new Socket(host, port);
            this.connection = new PeerConnection(socket);

            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            if (isInitiator) {
                // Step 1: Build PreKeyBundle and send as JSON string
                PreKeyBundle myBundle = PreKeyBundleBuilder.build(
                    keyStore.getLocalRegistrationId(), deviceId, keyStore);

                out.writeObject(userId);
                out.writeObject(PreKeyBundleDTO.fromPreKeyBundle(myBundle).toJson());
                out.flush();

                // Step 2: Receive peer userId and PreKeyBundle JSON string
                String peerId = (String) in.readObject();
                String peerBundleJson = (String) in.readObject();

                PreKeyBundle peerBundle = PreKeyBundleDTO.fromJson(peerBundleJson).toPreKeyBundle();

                SignalProtocolAddress peerAddress = new SignalProtocolAddress(peerId, deviceId);
                cryptoManager.initializeSession(peerAddress, peerBundle);

            } else {
                // Step 1: Receive peer userId and PreKeyBundle JSON string
                String peerId = (String) in.readObject();
                String peerBundleJson = (String) in.readObject();

                PreKeyBundle peerBundle = PreKeyBundleDTO.fromJson(peerBundleJson).toPreKeyBundle();

                // Step 2: Send own userId and PreKeyBundle JSON string back
                out.writeObject(userId);
                PreKeyBundle myBundle = PreKeyBundleBuilder.build(
                    keyStore.getLocalRegistrationId(), deviceId, keyStore);
                out.writeObject(PreKeyBundleDTO.fromPreKeyBundle(myBundle).toJson());
                out.flush();

                SignalProtocolAddress peerAddress = new SignalProtocolAddress(peerId, deviceId);
                cryptoManager.initializeSession(peerAddress, peerBundle);
            }

            System.out.println("Secure session established.");

        } catch (Exception e) {
            System.err.println("Failed to connect or establish session: " + e.getMessage());
            e.printStackTrace();
        }
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
