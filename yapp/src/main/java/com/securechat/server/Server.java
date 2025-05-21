package com.securechat.server;

import com.securechat.network.MessageRouter;
import com.securechat.network.PeerConnection;
import com.securechat.protocol.Packet;
import com.securechat.protocol.PacketType;
import com.securechat.protocol.dto.PreKeyBundleDTO;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The {@code Server} class represents the main entry point for the SecureChat backend server.
 * It accepts and manages client connections, routes messages, and handles cryptographic
 * pre-key bundle registration and lookup.
 * <p>
 * It uses a thread pool to concurrently handle client connections and a {@link MessageRouter}
 * to manage routing of messages between peers.
 * </p>
 *
 * @author
 * @version 0.2
 */
public class Server implements ConnectionListener {
    private static final Logger logger = LoggerFactory.getLogger(Server.class);

    private final int port;
    private final ExecutorService pool = Executors.newCachedThreadPool();
    private final MessageRouter messageRouter = new MessageRouter();
    private final ClientManager clientManager = new ClientManager();
    public static final String SYSTEM_SENDER_ID = "SERVER";
    public static final int SYSTEM_SENDER_DEVICE_ID = -1;

    private volatile boolean isRunning = true;

    /**
     * Constructs a {@code Server} instance listening on the specified port.
     *
     * @param port The TCP port on which the server will accept client connections.
     */
    public Server(int port) {
        this.port = port;
    }

    /**
     * Returns a prefix string used for logging purposes, specific to the server port.
     *
     * @return A formatted log prefix string.
     */
    private String prefix() {
        return "[Server-" + port + "]";
    }

    /**
     * Starts the server, begins accepting client connections, and dispatches
     * handlers for processing incoming packets. Runs indefinitely until stopped.
     */
    public void start() {
        Runtime.getRuntime().addShutdownHook(new Thread(this::stop));

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            logger.info("{} SecureChat server started and listening on port {}", prefix(), port);

            while (isRunning) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    clientSocket.setSoTimeout(30000);

                    PeerConnection conn = new PeerConnection(clientSocket);
                    logger.info("{} Accepted new client connection from {}", prefix(), clientSocket.getRemoteSocketAddress());

                    pool.execute(() -> handleClient(conn));
                } catch (Exception e) {
                    if (isRunning) {
                        logger.error("{} Error accepting client connection", prefix(), e);
                    } else {
                        logger.info("{} Server stopped accepting connections", prefix());
                    }
                }
            }
        } catch (Exception e) {
            logger.error("{} Server socket failed on port {}", prefix(), port, e);
        }
    }

    /**
     * Handles communication with a single client. Receives and processes packets,
     * handling registration, message routing, and error reporting.
     *
     * @param conn The {@link PeerConnection} representing the connected client.
     */
    private void handleClient(PeerConnection conn) {
        logger.info("{} Started client handler for {}", prefix(), conn);
        try {
            while (isRunning) {
                Object obj = conn.receiveMessageObject();

                if (!(obj instanceof Packet packet)) {
                    logger.warn("{} Expected Packet but received {} from {}", prefix(),
                            obj == null ? "null" : obj.getClass().getName(), conn);
                    continue;
                }

                String senderId = packet.getSenderId();
                int senderDeviceId = packet.getSenderDeviceId();

                switch (packet.getType()) {
                    case PREKEY_BUNDLE -> handlePreKeyBundleRegistration(packet, conn);
                    case GET_PREKEY_BUNDLE -> handlePreKeyBundleRequest(packet, conn);
                    case PREKEY_MESSAGE, MESSAGE, ACK -> {
                        try {
                            messageRouter.routeMessage(packet, senderId);
                            logger.info("{} Routed {} packet from user '{}' device '{}'", prefix(), packet.getType(), senderId, senderDeviceId);
                        } catch (Exception e) {
                            logger.error("{} Failed to route message from user '{}' device '{}'", prefix(), senderId, senderDeviceId, e);
                        }
                    }
                    default -> logger.warn("{} Unknown packet type '{}' from user '{}' device '{}'", prefix(), packet.getType(), senderId, senderDeviceId);
                }
            }
        } catch (Exception e) {
            logger.error("{} Client handler error for connection {}", prefix(), conn, e);
        } finally {
            try {
                conn.close();
                logger.info("{} Closed connection for client {}", prefix(), conn);
            } catch (Exception e) {
                logger.warn("{} Failed to close client connection {}", prefix(), conn, e);
            }
        }
    }

    /**
     * Handles registration of a pre-key bundle sent by a client.
     * This is required for clients to participate in encrypted messaging.
     *
     * @param packet The incoming {@link Packet} containing the pre-key bundle.
     * @param conn   The {@link PeerConnection} representing the client.
     */
    private void handlePreKeyBundleRegistration(Packet packet, PeerConnection conn) {
        String userId = packet.getSenderId();
        int deviceId = packet.getSenderDeviceId();
        PreKeyBundleDTO bundle = packet.getPreKeyBundlePayload();

        if (userId == null || userId.isEmpty() || deviceId < 0 || bundle == null) {
            logger.warn("{} Invalid PREKEY_BUNDLE registration packet from user '{}' device '{}'", prefix(), userId, deviceId);
            sendError(conn, "Invalid PREKEY_BUNDLE packet");
            return;
        }

        try {
            clientManager.register(userId, deviceId, bundle);
            messageRouter.registerPeer(userId, deviceId, conn);
            logger.info("{} Registered peer and PreKeyBundle for user '{}' device '{}'", prefix(), userId, deviceId);
        } catch (Exception e) {
            logger.error("{} Failed to register peer '{}' device '{}'", prefix(), userId, deviceId, e);
            sendError(conn, "Failed to register peer connection");
        }
    }

    /**
     * Handles a request to retrieve a user's pre-key bundle from another client.
     * This enables initial session establishment.
     *
     * @param packet The request {@link Packet}.
     * @param conn   The connection from which the request originated.
     */
    private void handlePreKeyBundleRequest(Packet packet, PeerConnection conn) {
        String requesterId = packet.getSenderId();
        String targetUserId = packet.getRecipientId();
        int targetDeviceId = packet.getRecipientDeviceId();

        if (targetUserId == null || targetUserId.isEmpty() || targetDeviceId < 0) {
            logger.warn("{} Invalid GET_PREKEY_BUNDLE request from '{}' for recipient '{}:{}'", prefix(), requesterId, targetUserId, targetDeviceId);
            sendError(conn, "Invalid recipient info");
            return;
        }

        PreKeyBundleDTO bundle = clientManager.getPreKeyBundle(targetUserId, targetDeviceId);

        if (bundle != null) {
            try {
                Packet response = new Packet();
                response.setType(PacketType.PREKEY_BUNDLE);
                response.setSenderId(targetUserId);
                response.setSenderDeviceId(targetDeviceId);
                response.setRecipientId(requesterId);
                response.setRecipientDeviceId(packet.getSenderDeviceId());
                response.setPreKeyBundlePayload(bundle);

                // Route via MessageRouter for tracking and routing consistency
                messageRouter.routePreKeyPacket(response, requesterId, packet.getSenderDeviceId());

                logger.info("{} Sent PREKEY_BUNDLE to requester '{}' for user '{}' device '{}'", prefix(), requesterId, targetUserId, targetDeviceId);
            } catch (Exception e) {
                logger.error("{} Failed to send PREKEY_BUNDLE to requester '{}'", prefix(), requesterId, e);
                sendError(conn, "Failed to send PreKeyBundle");
            }
        } else {
            logger.warn("{} No PreKeyBundle found for user '{}' device '{}'", prefix(), targetUserId, targetDeviceId);
            sendError(conn, "PreKeyBundle not found for recipient");
        }
    }

    /**
     * Sends an error {@link Packet} back to the client with a specified message.
     *
     * @param conn    The connection to send the error to.
     * @param message The human-readable error message.
     */
    private void sendError(PeerConnection conn, String message) {
        try {
            Packet errorPacket = new Packet();
            errorPacket.setType(PacketType.ERROR);
            errorPacket.setMessagePayload(message.getBytes(StandardCharsets.UTF_8));
            errorPacket.setSenderId(SYSTEM_SENDER_ID);
            errorPacket.setRecipientId(SYSTEM_SENDER_ID);
            errorPacket.setSenderDeviceId(SYSTEM_SENDER_DEVICE_ID);
            errorPacket.setRecipientDeviceId(SYSTEM_SENDER_DEVICE_ID);

            conn.sendMessageObject(errorPacket);
            logger.debug("{} Sent ERROR packet with message: {}", prefix(), message);
        } catch (Exception e) {
            logger.warn("{} Failed to send error packet: {}", prefix(), e.getMessage(), e);
        }
    }

    @Override
    public void onPeerConnected(String userId, int deviceId) {
        logger.info("{} Notifying user '{}' about device '{}' connection", prefix(), userId, deviceId);

        byte[] payload = ("User " + userId + " on device " + deviceId + " connected").getBytes(StandardCharsets.UTF_8);

        messageRouter.getConnectedDeviceIds(userId).stream()
            .filter(id -> id != deviceId)
            .forEach(otherDeviceId -> {
                Packet update = new Packet(
                    SYSTEM_SENDER_ID,
                    SYSTEM_SENDER_DEVICE_ID,
                    userId,
                    otherDeviceId,
                    payload,
                    PacketType.USER_CONNECTED
                );
                messageRouter.routeMessage(update, userId);
            });
    }

    @Override
    public void onPeerDisconnected(String userId, int deviceId) {
        logger.info("{} Notifying user '{}' about device '{}' disconnection", prefix(), userId, deviceId);

        byte[] payload = ("User " + userId + " on device " + deviceId + " disconnected").getBytes(StandardCharsets.UTF_8);

        messageRouter.getConnectedDeviceIds(userId).stream()
            .filter(id -> id != deviceId)
            .forEach(otherDeviceId -> {
                Packet update = new Packet(
                    SYSTEM_SENDER_ID,
                    SYSTEM_SENDER_DEVICE_ID,
                    userId,
                    otherDeviceId,
                    payload,
                    PacketType.USER_DISCONNECTED
                );
                messageRouter.routeMessage(update, userId);
            });
    }


    /**
     * Gracefully stops the server, shutting down the thread pool and ceasing
     * to accept new client connections.
     */
    public void stop() {
        isRunning = false;
        pool.shutdownNow();
        logger.info("{} Server stopped", prefix());
    }
}
