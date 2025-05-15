package com.securechat.server;

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
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Server {
    private final int port;
    private final SignalKeyStore keyStore;
    private final ExecutorService pool = Executors.newCachedThreadPool();

    public Server(int port, SignalKeyStore keyStore) {
        this.port = port;
        this.keyStore = keyStore;
    }

    public void start() {
        try (java.net.ServerSocket serverSocket = new java.net.ServerSocket(port)) {
            System.out.println("Server started on port " + port);
            while (true) {
                java.net.Socket clientSocket = serverSocket.accept();
                PeerConnection conn = new PeerConnection(clientSocket);
                pool.execute(() -> handleClient(conn));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void handleClient(PeerConnection conn) {
        SignalProtocolManager cryptoManager = new SignalProtocolManager(keyStore);
        final int deviceId = 1;

        try {
            ObjectOutputStream out = new ObjectOutputStream(conn.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(conn.getInputStream());

            // Step 1: Receive peer userId and PreKeyBundle JSON string
            String peerId = (String) in.readObject();
            String peerBundleJson = (String) in.readObject();

            // Deserialize the JSON string to PreKeyBundle using DTO
            PreKeyBundle peerBundle = PreKeyBundleDTO.fromJson(peerBundleJson).toPreKeyBundle();

            // Step 2: Send own userId and PreKeyBundle JSON string back
            String myUserId = "server";
            PreKeyBundle myBundle = PreKeyBundleBuilder.build(
                keyStore.getLocalRegistrationId(), deviceId, keyStore);

            String myBundleJson = PreKeyBundleDTO.fromPreKeyBundle(myBundle).toJson();

            out.writeObject(myUserId);
            out.writeObject(myBundleJson);
            out.flush();

            // Step 3: Initialize session with peer's bundle
            SignalProtocolAddress peerAddress = new SignalProtocolAddress(peerId, deviceId);
            cryptoManager.initializeSession(peerAddress, peerBundle);

            System.out.println("Secure session established with " + peerId);

            // Step 4: Relay messages or echo back
            while (true) {
                String received = conn.receive();
                if (received == null) break;

                Message msg = MessageSerializer.deserialize(received);
                if (msg == null) {
                    System.err.println("Received invalid message JSON");
                    continue;
                }

                SignalProtocolAddress senderAddr = new SignalProtocolAddress(msg.getSender(), deviceId);
                byte[] ciphertext = Base64.getDecoder().decode(msg.getEncryptedPayload());
                String plaintext = cryptoManager.decryptMessage(senderAddr, ciphertext);
                System.out.println("Received from " + msg.getSender() + ": " + plaintext);

                byte[] encryptedResponse = cryptoManager.encryptMessage(senderAddr, "Echo: " + plaintext);
                String encodedResponse = Base64.getEncoder().encodeToString(encryptedResponse);

                Message response = new Message(
                    java.util.UUID.randomUUID().toString(),
                    myUserId,
                    msg.getSender(),
                    "TEXT",
                    encodedResponse
                );
                conn.send(MessageSerializer.serialize(response));
            }

        } catch (Exception e) {
            System.err.println("Error handling client: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try {
                conn.close();
            } catch (Exception ignored) {}
        }
    }
}
