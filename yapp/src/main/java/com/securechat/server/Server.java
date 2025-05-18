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

    public void start() {
        Runtime.getRuntime().addShutdownHook(new Thread(this::stop));

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            logger.info("SecureChat server started on port {}", port);

            while (isRunning) {
                Socket clientSocket = serverSocket.accept();
                clientSocket.setSoTimeout(30000);

                PeerConnection conn = new PeerConnection(clientSocket);
                pool.execute(() -> handleClient(conn));
            }
        } catch (Exception e) {
            logger.error("Server error", e);
        }
    }

    private void handleClient(PeerConnection conn) {
        try {
            while (isRunning) {
                Object obj = conn.receiveMessageObject();
                if (!(obj instanceof Packet packet)) {
                    logger.warn("Expected Packet but got: {}", obj == null ? "null" : obj.getClass());
                    continue;
                }

                switch (packet.getType()) {
                    case PREKEY_BUNDLE -> handlePreKeyBundleRegistration(packet, conn);
                    case GET_PREKEY_BUNDLE -> handlePreKeyBundleRequest(packet, conn);
                    case PREKEY_MESSAGE, MESSAGE -> messageRouter.routeMessage(packet, packet.getSenderId());
                    default -> logger.warn("Unknown packet type: {}", packet.getType());
                }
            }
        } catch (Exception e) {
            logger.error("Client handler error", e);
        } finally {
            try {
                conn.close();
            } catch (Exception e) {
                logger.warn("Failed to close connection", e);
            }
        }
    }

    private void handlePreKeyBundleRegistration(Packet packet, PeerConnection conn) {
        String userId = packet.getSenderId();
        int deviceId = packet.getSenderDeviceId();
        PreKeyBundleDTO bundle = packet.getPreKeyBundlePayload();

        if (userId == null || userId.isEmpty() || deviceId < 0 || bundle == null) {
            logger.warn("Invalid PREKEY_BUNDLE registration packet");
            sendError(conn, "Invalid PREKEY_BUNDLE packet");
            return;
        }

        peerBundles.computeIfAbsent(userId, k -> new ConcurrentHashMap<>())
                .put(deviceId, bundle);

        messageRouter.registerPeer(userId, deviceId, conn);
        logger.info("Registered prekey bundle for user '{}' device {}", userId, deviceId);
    }

    private void handlePreKeyBundleRequest(Packet packet, PeerConnection conn) {
        // Use sender and recipient IDs from the packet directly
        String requesterId = packet.getSenderId();
        int requesterDeviceId = packet.getSenderDeviceId();

        String targetUserId = packet.getRecipientId();
        int targetDeviceId = packet.getRecipientDeviceId();

        if (targetUserId == null || targetUserId.isEmpty() || targetDeviceId < 0) {
            logger.warn("Invalid GET_PREKEY_BUNDLE request from '{}'", requesterId);
            sendError(conn, "Invalid recipient info");
            return;
        }

        PreKeyBundleDTO bundle = getPreKeyBundle(targetUserId, targetDeviceId);
        if (bundle != null) {
            try {
                Packet response = new Packet(
                    targetUserId,
                    targetDeviceId,
                    requesterId,
                    requesterDeviceId,
                    bundle
                );
                conn.sendMessageObject(response);
                logger.info("Sent PREKEY_BUNDLE to '{}' for user '{}' device {}", requesterId, targetUserId, targetDeviceId);
            } catch (Exception e) {
                logger.error("Failed to send PREKEY_BUNDLE to '{}'", requesterId, e);
            }
        } else {
            logger.warn("No prekey bundle found for {} device {}", targetUserId, targetDeviceId);
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
        } catch (Exception e) {
            logger.warn("Failed to send error packet: {}", e.getMessage());
        }
    }

    public void stop() {
        isRunning = false;
        pool.shutdownNow();
        logger.info("Server stopped");
    }
}
