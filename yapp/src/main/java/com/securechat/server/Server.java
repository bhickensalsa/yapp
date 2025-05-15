package com.securechat.server;

import com.securechat.crypto.libsignal.PreKeyBundleDTO;
import com.securechat.crypto.libsignal.SignalKeyStore;
import com.securechat.crypto.libsignal.SignalProtocolManager;
import com.securechat.network.MessageRouter;
import com.securechat.network.PeerConnection;
import com.securechat.protocol.Message;
import com.securechat.store.PreKeyStore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.PreKeyBundle;

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
    private final MessageRouter messageRouter = new MessageRouter();

    public Server(int port, SignalKeyStore keyStore, PreKeyStore preKeyStore) {
        this.port = port;
        this.keyStore = keyStore;
        this.preKeyStore = preKeyStore;
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

        try {
            // Step 1: Receive userId and PreKeyBundle JSON
            String userId = (String) conn.receiveObject();
            String preKeyBundleJson = (String) conn.receiveObject();

            logger.debug("Received registration from user '{}'", userId);

            PreKeyBundleDTO preKeyBundleDTO = PreKeyBundleDTO.fromJson(preKeyBundleJson);
            preKeyStore.registerPreKeyBundle(userId, deviceId, preKeyBundleDTO);
            logger.info("Registered prekey bundle for user '{}'", userId);

            // Step 2: Initialize session with peer's PreKeyBundle
            PreKeyBundle peerBundle = preKeyBundleDTO.toPreKeyBundle();
            SignalProtocolAddress peerAddress = new SignalProtocolAddress(userId, deviceId);
            cryptoManager.initializeSession(peerAddress, peerBundle);
            logger.info("Secure session established with user '{}'", userId);

            // Step 3: Register this user’s output stream with MessageRouter
            messageRouter.registerPeer(userId, conn);

            // Step 4: Listen for incoming objects and route them
            while (true) {
                Object obj = conn.receiveObject();

                if (obj instanceof String) {
                    // Handle control commands, e.g. "GET_PREKEY_BUNDLE:bob"
                    String command = (String) obj;
                    logger.debug("Received command from '{}': {}", userId, command);

                    if (command.startsWith("GET_PREKEY_BUNDLE:")) {
                        String requestedUser = command.substring("GET_PREKEY_BUNDLE:".length());
                        PreKeyBundleDTO requestedDTO = preKeyStore.getPreKeyBundle(requestedUser, deviceId);

                        if (requestedDTO != null) {
                            conn.sendObject("PREKEY_BUNDLE:" + requestedDTO.toJson());
                            logger.info("Served prekey bundle for '{}'", requestedUser);
                        } else {
                            conn.sendObject("ERROR: User " + requestedUser + " prekey bundle not found");
                            logger.warn("Requested prekey bundle for unknown user '{}'", requestedUser);
                        }
                    }
                } else if (obj instanceof Message) {
                    Message msg = (Message) obj;
                    logger.info("Received message from '{}': routing to '{}'", msg.getSender(), msg.getRecipient());

                    // Route the message to the recipient via the MessageRouter
                    messageRouter.routeMessage(msg);
                } else {
                    logger.warn("Received unknown object type from user '{}': {}", userId, obj.getClass());
                }
            }

        } catch (Exception e) {
            logger.error("Error handling client '{}': {}", conn.getRemoteAddress(), e.getMessage(), e);
        } finally {
            try {
                conn.close();
            } catch (Exception e) {
                logger.warn("Failed to close connection cleanly", e);
            }
        }
    }
}
