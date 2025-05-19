package com.securechat.server;

import com.securechat.crypto.libsignal.PreKeyBundleDTO;
import com.securechat.network.MessageRouter;
import com.securechat.network.PeerConnection;
import com.securechat.protocol.Packet;
import com.securechat.protocol.PacketType;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Server {
    private static final Logger logger = LoggerFactory.getLogger(Server.class);

    private final int port;
    private final ExecutorService pool = Executors.newCachedThreadPool();
    private final MessageRouter messageRouter = new MessageRouter();

    // Map of userId -> deviceId -> PreKeyBundleDTO
    private final Map<String, Map<Integer, PreKeyBundleDTO>> peerBundles = new ConcurrentHashMap<>();

    private volatile boolean isRunning = true;

    public Server(int port) {
        this.port = port;
    }

    private String prefix() {
        return "[Server-" + port + "]";
    }

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

    private void handlePreKeyBundleRegistration(Packet packet, PeerConnection conn) {
        String userId = packet.getSenderId();
        int deviceId = packet.getSenderDeviceId();
        PreKeyBundleDTO bundle = packet.getPreKeyBundlePayload();

        if (userId == null || userId.isEmpty() || deviceId < 0 || bundle == null) {
            logger.warn("{} Invalid PREKEY_BUNDLE registration packet from user '{}' device '{}'", prefix(), userId, deviceId);
            sendError(conn, "Invalid PREKEY_BUNDLE packet");
            return;
        }

        peerBundles.computeIfAbsent(userId, k -> new ConcurrentHashMap<>())
                   .put(deviceId, bundle);

        try {
            messageRouter.registerPeer(userId, deviceId, conn);
            logger.info("{} Registered PreKeyBundle for user '{}' device '{}'", prefix(), userId, deviceId);
        } catch (Exception e) {
            logger.error("{} Failed to register peer '{}' device '{}'", prefix(), userId, deviceId, e);
            sendError(conn, "Failed to register peer connection");
        }
    }

    private void handlePreKeyBundleRequest(Packet packet, PeerConnection conn) {
        String requesterId = packet.getSenderId();
        String targetUserId = packet.getRecipientId();
        int targetDeviceId = packet.getRecipientDeviceId();

        if (targetUserId == null || targetUserId.isEmpty() || targetDeviceId < 0) {
            logger.warn("{} Invalid GET_PREKEY_BUNDLE request from '{}' for recipient '{}:{}'", prefix(), requesterId, targetUserId, targetDeviceId);
            sendError(conn, "Invalid recipient info");
            return;
        }

        PreKeyBundleDTO bundle = getPreKeyBundle(targetUserId, targetDeviceId);

        if (bundle != null) {
            try {
                Packet response = new Packet(targetUserId, targetDeviceId, bundle);
                conn.sendMessageObject(response);
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

    private PreKeyBundleDTO getPreKeyBundle(String userId, int deviceId) {
        Map<Integer, PreKeyBundleDTO> deviceMap = peerBundles.get(userId);
        if (deviceMap != null) {
            return deviceMap.get(deviceId);
        }
        return null;
    }

    private void sendError(PeerConnection conn, String message) {
        try {
            Packet errorPacket = new Packet();
            errorPacket.setType(PacketType.ERROR);
            errorPacket.setMessagePayload(message.getBytes(StandardCharsets.UTF_8));
            errorPacket.setSenderId(null);
            errorPacket.setRecipientId(null);
            errorPacket.setSenderDeviceId(-1);
            errorPacket.setRecipientDeviceId(-1);

            conn.sendMessageObject(errorPacket);
            logger.debug("{} Sent ERROR packet with message: {}", prefix(), message);
        } catch (Exception e) {
            logger.warn("{} Failed to send error packet: {}", prefix(), e.getMessage(), e);
        }
    }

    public void stop() {
        isRunning = false;
        pool.shutdownNow();
        logger.info("{} Server stopped", prefix());
    }
}
