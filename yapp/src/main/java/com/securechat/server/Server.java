package com.securechat.server;

import com.securechat.crypto.libsignal.PreKeyBundleDTO;
import com.securechat.crypto.libsignal.SignalKeyStore;
import com.securechat.network.MessageRouter;
import com.securechat.network.PeerConnection;
import com.securechat.protocol.Message;
import com.securechat.protocol.Packet;
import com.securechat.protocol.PacketType;
import com.securechat.store.PreKeyStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Server {
    private static final Logger logger = LoggerFactory.getLogger(Server.class);

    private final int messagePort;
    private final int preKeyPort;
    private final SignalKeyStore keyStore;
    private final PreKeyStore preKeyStore;
    private final ExecutorService pool = Executors.newCachedThreadPool();
    private final MessageRouter messageRouter = new MessageRouter();
    private final int deviceId = 1; // TODO: Make configurable if supporting multi-device

    private volatile boolean isRunning = true;

    public Server(int messagePort, int preKeyPort, SignalKeyStore keyStore, PreKeyStore preKeyStore) {
        this.messagePort = messagePort;
        this.preKeyPort = preKeyPort;
        this.keyStore = keyStore;
        this.preKeyStore = preKeyStore;
    }

    public void start() {
        try (
            ServerSocket messageServerSocket = new ServerSocket(messagePort);
            ServerSocket preKeyServerSocket = new ServerSocket(preKeyPort)
        ) {
            logger.info("SecureChat server started on message port {} and preKey port {}", messagePort, preKeyPort);

            while (isRunning) {
                try {
                    Socket messageSocket = messageServerSocket.accept();
                    logger.info("Accepted message connection from {}", messageSocket.getRemoteSocketAddress());

                    Socket preKeySocket = preKeyServerSocket.accept();
                    logger.info("Accepted preKey connection from {}", preKeySocket.getRemoteSocketAddress());

                    PeerConnection conn = new PeerConnection(messageSocket, preKeySocket);
                    pool.execute(() -> handleClient(conn));
                } catch (Exception e) {
                    logger.error("Error accepting new connection", e);
                }
            }
        } catch (Exception e) {
            logger.error("Server encountered a fatal error during startup", e);
        }
    }

    public void stop() {
        isRunning = false;
        try {
            pool.shutdownNow();
            logger.info("Server shutdown initiated.");
        } catch (Exception e) {
            logger.warn("Error while shutting down the server", e);
        }
    }

    private void handleClient(PeerConnection conn) {
        try {
            String userId = receiveUserId(conn);
            if (userId == null) return;

            if (!registerPreKey(conn, userId)) return;

            messageRouter.registerPeer(userId, conn);
            logger.info("Registered user '{}' with message router", userId);

            pool.execute(() -> handlePreKeyPackets(conn, userId, deviceId));
            processIncomingPackets(conn, userId);
        } catch (Exception e) {
            logger.error("Error handling client '{}': {}", conn.getRemoteAddress(), e.getMessage(), e);
        } finally {
            try {
                conn.close();
            } catch (Exception e) {
                logger.warn("Failed to close connection cleanly for {}", conn.getRemoteAddress(), e);
            }
        }
    }

    private String receiveUserId(PeerConnection conn) {
        try {
            Object obj = conn.receiveMessageObject();
            if (obj instanceof String userId) {
                logger.debug("Received userId '{}'", userId);
                return userId;
            } else {
                logger.error("Expected userId (String), but got: {}", obj.getClass());
                conn.close();
                return null;
            }
        } catch (Exception e) {
            logger.error("Failed to receive userId", e);
            return null;
        }
    }

    private boolean registerPreKey(PeerConnection conn, String userId) {
        try {
            Object obj = conn.receivePreKeyObject();
            if (!(obj instanceof Packet packet)) {
                logger.error("Expected Packet on preKey stream, got: {}", obj.getClass());
                conn.close();
                return false;
            }

            if (packet.getType() != PacketType.PREKEY_BUNDLE || !(packet.getPayload() instanceof PreKeyBundleDTO bundle)) {
                logger.error("Invalid PREKEY_BUNDLE payload from '{}': {}", userId, packet.getType());
                conn.close();
                return false;
            }

            preKeyStore.registerPreKeyBundle(userId, deviceId, bundle);
            logger.info("Registered prekey bundle for user '{}'", userId);
            return true;
        } catch (Exception e) {
            logger.error("Error registering prekey for '{}': {}", userId, e.getMessage(), e);
            return false;
        }
    }

    private void processIncomingPackets(PeerConnection conn, String userId) {
        try {
            while (isRunning) {
                Object obj = conn.receiveMessageObject();
                if (!(obj instanceof Packet packet)) {
                    logger.warn("Received invalid message packet from '{}': {}", userId, obj.getClass());
                    continue;
                }

                switch (packet.getType()) {
                    case MESSAGE -> {
                        if (packet.getPayload() instanceof Message msg) {
                            logger.info("Routing message from '{}' to '{}'", msg.getSender(), msg.getRecipient());
                            messageRouter.routeMessage(msg);
                        } else {
                            logger.warn("Invalid MESSAGE payload from '{}'", userId);
                        }
                    }

                    case ACK, ERROR, COMMAND -> {
                        logger.debug("Received {} packet from '{}': {}", packet.getType(), userId, packet.getPayload());
                    }

                    default -> logger.warn("Unknown packet type from '{}': {}", userId, packet.getType());
                }
            }
        } catch (Exception e) {
            logger.error("Error processing messages for '{}': {}", userId, e.getMessage(), e);
        }
    }

    private void handlePreKeyPackets(PeerConnection conn, String userId, int deviceId) {
        try {
            while (isRunning) {
                Object obj = conn.receivePreKeyObject();
                if (!(obj instanceof Packet packet)) {
                    logger.warn("Received invalid preKey packet from '{}': {}", userId, obj.getClass());
                    continue;
                }

                switch (packet.getType()) {
                    case GET_PREKEY_BUNDLE -> {
                        if (packet.getPayload() instanceof String targetUser) {
                            PreKeyBundleDTO bundle = preKeyStore.getPreKeyBundle(targetUser, deviceId);
                            if (bundle != null) {
                                conn.sendPreKeyObject(new Packet(PacketType.PREKEY_BUNDLE, bundle));
                                logger.info("Sent preKey bundle for '{}'", targetUser);
                            } else {
                                conn.sendPreKeyObject(new Packet(PacketType.ERROR, "PreKey bundle not found for: " + targetUser));
                                logger.warn("PreKey bundle not found for '{}'", targetUser);
                            }
                        }
                    }

                    case ACK, ERROR, COMMAND -> {
                        logger.debug("Received {} on preKey stream from '{}': {}", packet.getType(), userId, packet.getPayload());
                    }

                    default -> logger.warn("Unknown preKey packet type from '{}': {}", userId, packet.getType());
                }
            }
        } catch (Exception e) {
            logger.error("Error handling preKey packets for '{}': {}", userId, e.getMessage(), e);
        }
    }
}
