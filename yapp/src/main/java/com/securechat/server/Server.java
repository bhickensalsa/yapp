package com.securechat.server;

import com.securechat.crypto.libsignal.PreKeyBundleBuilder;
import com.securechat.crypto.libsignal.PreKeyBundleDTO;
import com.securechat.crypto.libsignal.SignalKeyStore;
import com.securechat.crypto.libsignal.SignalProtocolManager;
import com.securechat.network.PeerConnection;
import com.securechat.store.PreKeyStore;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.PreKeyBundle;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Server {
    private final int port;
    private final SignalKeyStore keyStore;
    private final PreKeyStore preKeyStore;
    private final ExecutorService pool = Executors.newCachedThreadPool();

    // Store server's preKeyId and signedPreKeyId
    private final int serverPreKeyId;
    private final int serverSignedPreKeyId;

    public Server(int port, SignalKeyStore keyStore, PreKeyStore preKeyStore, int serverPreKeyId, int serverSignedPreKeyId) {
        this.port = port;
        this.keyStore = keyStore;
        this.preKeyStore = preKeyStore;
        this.serverPreKeyId = serverPreKeyId;
        this.serverSignedPreKeyId = serverSignedPreKeyId;
    }

    public void start() {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server started on port " + port);
            while (true) {
                Socket clientSocket = serverSocket.accept();
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

        try (ObjectOutputStream out = new ObjectOutputStream(conn.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(conn.getInputStream())) {

            // Step 1: Receive peer userId and PreKeyBundle JSON string
            String peerId = (String) in.readObject();
            String peerBundleJson = (String) in.readObject();

            PreKeyBundleDTO peerBundleDTO = PreKeyBundleDTO.fromJson(peerBundleJson);
            preKeyStore.registerPreKeyBundle(peerId, deviceId, peerBundleDTO);
            System.out.println("Registered prekey bundle for user: " + peerId);

            /* // Step 2: Send server's own PreKeyBundle, pass correct preKeyId/signedPreKeyId
            String myUserId = "server";
            PreKeyBundle myBundle = PreKeyBundleBuilder.build(
                keyStore.getLocalRegistrationId(),
                deviceId,
                keyStore,
                serverPreKeyId,
                serverSignedPreKeyId
            );
            String myBundleJson = PreKeyBundleDTO.fromPreKeyBundle(myBundle).toJson();
            out.writeObject(myUserId);
            out.writeObject(myBundleJson);
            out.flush(); */

            // Step 3: Initialize session with peer
            PreKeyBundle peerBundle = peerBundleDTO.toPreKeyBundle();
            SignalProtocolAddress peerAddress = new SignalProtocolAddress(peerId, deviceId);
            cryptoManager.initializeSession(peerAddress, peerBundle);
            System.out.println("Secure session established with " + peerId);

            // Step 4: Handle incoming requests
            while (true) {
                String received = conn.receive();
                if (received == null) break;

                if (received.startsWith("GET_PREKEY_BUNDLE:")) {
                    String requestedUser = received.substring("GET_PREKEY_BUNDLE:".length());
                    PreKeyBundleDTO requestedDTO = preKeyStore.getPreKeyBundle(requestedUser, deviceId);

                    if (requestedDTO != null) {
                        out.writeObject("PREKEY_BUNDLE:" + requestedDTO.toJson());
                    } else {
                        out.writeObject("ERROR: User " + requestedUser + " prekey bundle not found");
                    }
                    out.flush();
                    continue;
                }

                // Handle encrypted or other message types...
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                conn.close();
            } catch (Exception ignored) {}
        }
    }
}
