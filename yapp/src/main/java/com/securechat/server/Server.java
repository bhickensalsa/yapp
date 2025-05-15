package com.securechat.server;

import com.securechat.crypto.libsignal.PreKeyBundleDTO;
import com.securechat.crypto.libsignal.SignalKeyStore;
import com.securechat.crypto.libsignal.SignalProtocolManager;
import com.securechat.network.PeerConnection;
import com.securechat.store.PreKeyStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.PreKeyBundle;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Server {
    private static final Logger logger = LoggerFactory.getLogger(Server.class);

    private final int port;
    private final SignalKeyStore keyStore;
    private final PreKeyStore preKeyStore;
    private final ExecutorService pool = Executors.newCachedThreadPool();

    /* private final int serverPreKeyId;
    private final int serverSignedPreKeyId; */

    public Server(int port, SignalKeyStore keyStore, PreKeyStore preKeyStore) { // Add /* int serverPreKeyId, int serverSignedPreKeyId for Step 2.*/
        this.port = port;
        this.keyStore = keyStore;
        this.preKeyStore = preKeyStore;
        /* this.serverPreKeyId = serverPreKeyId;
        this.serverSignedPreKeyId = serverSignedPreKeyId; */
    }

    public void start() {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            logger.info("SecureChat server started on port {}", port);
            while (true) {
                Socket clientSocket = serverSocket.accept();
                logger.info("Accepted connection from {}", clientSocket.getRemoteSocketAddress());
                PeerConnection conn = new PeerConnection(clientSocket);
                pool.execute(() -> handleClient(conn));
            }
        } catch (Exception e) {
            logger.error("Server encountered a fatal error", e);
        }
    }

    private void handleClient(PeerConnection conn) {
        SignalProtocolManager cryptoManager = new SignalProtocolManager(keyStore);
        final int deviceId = 1;

        try (ObjectOutputStream out = new ObjectOutputStream(conn.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(conn.getInputStream())) {

            // Step 1: Receive peer userId and PreKeyBundle JSON
            String peerId = (String) in.readObject();
            String peerBundleJson = (String) in.readObject();

            logger.debug("Received registration from peer: {}", peerId);

            PreKeyBundleDTO peerBundleDTO = PreKeyBundleDTO.fromJson(peerBundleJson);
            preKeyStore.registerPreKeyBundle(peerId, deviceId, peerBundleDTO);
            logger.info("Registered prekey bundle for peer: {}", peerId);

            /*
            // Step 2: Send server's own PreKeyBundle (currently disabled)
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
            out.flush();
            */

            // Step 3: Establish session with peer
            PreKeyBundle peerBundle = peerBundleDTO.toPreKeyBundle();
            SignalProtocolAddress peerAddress = new SignalProtocolAddress(peerId, deviceId);
            cryptoManager.initializeSession(peerAddress, peerBundle);
            logger.info("Secure session established with peer: {}", peerId);

            // Step 4: Handle communication
            while (true) {
                String received = conn.receive();
                if (received == null) {
                    logger.info("Connection with {} closed by client", peerId);
                    break;
                }

                logger.debug("Received request from {}: {}", peerId, received);

                if (received.startsWith("GET_PREKEY_BUNDLE:")) {
                    String requestedUser = received.substring("GET_PREKEY_BUNDLE:".length());
                    PreKeyBundleDTO requestedDTO = preKeyStore.getPreKeyBundle(requestedUser, deviceId);

                    if (requestedDTO != null) {
                        out.writeObject("PREKEY_BUNDLE:" + requestedDTO.toJson());
                        logger.info("Served prekey bundle for {}", requestedUser);
                    } else {
                        out.writeObject("ERROR: User " + requestedUser + " prekey bundle not found");
                        logger.warn("Requested prekey bundle for unknown user: {}", requestedUser);
                    }
                    out.flush();
                }
            }

        } catch (Exception e) {
            logger.error("Error while handling client session", e);
        } finally {
            try {
                conn.close();
                logger.info("Closed connection with client");
            } catch (Exception e) {
                logger.warn("Failed to close connection cleanly", e);
            }
        }
    }
}
