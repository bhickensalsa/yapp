package com.securechat.server;

import com.securechat.crypto.libsignal.PreKeyBundleDTO;
import com.securechat.crypto.libsignal.SignalKeyStore;
import com.securechat.network.MessageRouter;
import com.securechat.network.PeerConnection;
import com.securechat.protocol.Packet;
import com.securechat.protocol.PacketType;
import com.securechat.store.PreKeyStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.DataInputStream;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ConcurrentHashMap;
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

    // Store sockets waiting to be paired by userId
    private final ConcurrentHashMap<String, Socket> pendingMessageSockets = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Socket> pendingPreKeySockets = new ConcurrentHashMap<>();

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

            // Thread for accepting message sockets
            Thread messageAcceptThread = new Thread(() -> {
                while (isRunning) {
                    try {
                        Socket messageSocket = messageServerSocket.accept();
                        logger.info("Accepted message connection from {}", messageSocket.getRemoteSocketAddress());
                        String userId = readUserIdFromSocket(messageSocket);
                        if (userId == null) {
                            logger.warn("Failed to read userId from message socket {}", messageSocket.getRemoteSocketAddress());
                            messageSocket.close();
                            continue;
                        }
                        pendingMessageSockets.put(userId, messageSocket);
                        tryPair(userId);
                    } catch (Exception e) {
                        if (isRunning) logger.error("Error accepting message connection", e);
                    }
                }
            }, "MessageAcceptThread");

            // Thread for accepting preKey sockets
            Thread preKeyAcceptThread = new Thread(() -> {
                while (isRunning) {
                    try {
                        Socket preKeySocket = preKeyServerSocket.accept();
                        logger.info("Accepted preKey connection from {}", preKeySocket.getRemoteSocketAddress());
                        String userId = readUserIdFromSocket(preKeySocket);
                        if (userId == null) {
                            logger.warn("Failed to read userId from preKey socket {}", preKeySocket.getRemoteSocketAddress());
                            preKeySocket.close();
                            continue;
                        }
                        pendingPreKeySockets.put(userId, preKeySocket);
                        tryPair(userId);
                    } catch (Exception e) {
                        if (isRunning) logger.error("Error accepting preKey connection", e);
                    }
                }
            }, "PreKeyAcceptThread");

            messageAcceptThread.start();
            preKeyAcceptThread.start();

            // Wait for threads to exit (e.g. on stop)
            messageAcceptThread.join();
            preKeyAcceptThread.join();

        } catch (Exception e) {
            logger.error("Server encountered a fatal error during startup", e);
        }
    }

    private void tryPair(String userId) {
        Socket msgSocket = pendingMessageSockets.get(userId);
        Socket preKeySocket = pendingPreKeySockets.get(userId);
        if (msgSocket != null && preKeySocket != null) {
            // Remove sockets from pending maps
            pendingMessageSockets.remove(userId);
            pendingPreKeySockets.remove(userId);

            logger.info("Pairing sockets for user '{}'", userId);
            try {
                PeerConnection conn = new PeerConnection(msgSocket, preKeySocket);
                pool.execute(() -> handleClient(conn));
            } catch (Exception e) {
                logger.error("Failed to create PeerConnection for '{}'", userId, e);
                try {
                    msgSocket.close();
                    preKeySocket.close();
                } catch (Exception ex) {
                    logger.warn("Error closing sockets for '{}'", userId, ex);
                }
            }
        }
    }

    /**
     * Reads the userId as a String sent by the client immediately upon socket connection.
     * This assumes client sends userId as a UTF string or similar.
     */
    private String readUserIdFromSocket(Socket socket) {
        try {
            InputStream in = socket.getInputStream();
            DataInputStream dataIn = new DataInputStream(in);
            // Assuming client sends UTF string userId immediately upon connect
            String userId = dataIn.readUTF();
            logger.debug("Read userId '{}' from socket {}", userId, socket.getRemoteSocketAddress());
            return userId;
        } catch (Exception e) {
            logger.error("Failed to read userId from socket {}", socket.getRemoteSocketAddress(), e);
            return null;
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

    // Existing methods mostly unchanged except minor tweaks

    private void handleClient(PeerConnection conn) {
        try {
            // userId already read on raw socket; here we re-read from message stream for safety
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

            if (packet.getType() != PacketType.PREKEY_BUNDLE || packet.getPreKeyBundlePayload() == null) {
                logger.error("Invalid PREKEY_BUNDLE payload from '{}': {}", userId, packet.getType());
                conn.close();
                return false;
            }

            PreKeyBundleDTO bundle = packet.getPreKeyBundlePayload();
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
                        byte[] messagePayload = packet.getMessagePayload();
                        if (messagePayload != null) {
                            messageRouter.routeMessage(packet, userId);
                        } else {
                            logger.warn("Invalid MESSAGE payload from '{}': payload is null", userId);
                        }
                    }
                    case ACK, ERROR, COMMAND -> {
                        logger.debug("Received {} packet from '{}': {}", packet.getType(), userId, packet.getStringPayload());
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
                    case MESSAGE, PREKEY_MESSAGE -> {
                        byte[] messagePayload = packet.getMessagePayload();
                        if (messagePayload != null) {
                            messageRouter.routeMessage(packet, userId);
                        } else {
                            logger.warn("Invalid {} payload from '{}': payload is null", packet.getType(), userId);
                        }
                    }
                    case ACK, ERROR, COMMAND -> {
                        logger.debug("Received {} packet from '{}': {}", packet.getType(), userId, packet.getStringPayload());
                    }
                    default -> logger.warn("Unknown packet type from '{}': {}", userId, packet.getType());
                }
            }
        } catch (Exception e) {
            logger.error("Error handling preKey packets for '{}': {}", userId, e.getMessage(), e);
        }
    }
}
