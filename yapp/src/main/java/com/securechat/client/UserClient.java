package com.securechat.client;

import com.securechat.crypto.libsignal.SignalProtocolManager;
import com.securechat.crypto.libsignal.PreKeyBundleBuilder;
import com.securechat.crypto.libsignal.PreKeyBundleDTO;
import com.securechat.network.PeerConnection;
import com.securechat.protocol.Packet;
import com.securechat.protocol.PacketType;
import com.securechat.store.SignalStore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.SessionBuilder;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.util.KeyHelper;

import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class UserClient {
    private static final Logger logger = LoggerFactory.getLogger(UserClient.class);

    private final String userId;
    private final int userDeviceId;

    private final SignalStore signalStore;
    private final SignalProtocolManager SPManager;

    private final int preKeyId;
    private final int signedPreKeyId;

    private PeerConnection connection;
    private PreKeyBundle myBundle;

    // Map peerId:PacketType to pending requests
    private final java.util.Map<String, CompletableFuture<Packet>> pendingRequests = new java.util.concurrent.ConcurrentHashMap<>();

    private final ExecutorService pool = Executors.newCachedThreadPool();

    public UserClient(String userId, int userDeviceId, SignalStore signalStore, int preKeyId, int signedPreKeyId) {
        this.userId = userId;
        this.userDeviceId = userDeviceId;
        this.signalStore = signalStore;
        this.SPManager = new SignalProtocolManager(signalStore);
        this.preKeyId = preKeyId;
        this.signedPreKeyId = signedPreKeyId;
    }

    public void initializeUser() {
        logger.info("[{}] Initializing user keys with PreKeyId={} and SignedPreKeyId={}", userId, preKeyId, signedPreKeyId);
        try {
            IdentityKeyPair identityKeyPair = KeyHelper.generateIdentityKeyPair();
            int registrationId = KeyHelper.generateRegistrationId(false);

            signalStore.initializeKeys(identityKeyPair, registrationId);

            var preKey = KeyHelper.generatePreKeys(preKeyId, 1).get(0);
            var signedPreKey = KeyHelper.generateSignedPreKey(identityKeyPair, signedPreKeyId);

            signalStore.storePreKey(preKeyId, preKey);
            signalStore.storeSignedPreKey(signedPreKeyId, signedPreKey);

            logger.info("[{}] User keys initialized successfully", userId);
        } catch (Exception e) {
            logger.error("[{}] Failed to initialize user keys", userId, e);
        }
    }

    public void connectToServer(String host, int port) throws Exception {
        logger.info("[{}] Connecting to server at {}:{}", userId, host, port);
        try {
            Socket socket = new Socket(host, port);
            this.connection = new PeerConnection(socket);

            myBundle = PreKeyBundleBuilder.build(
                signalStore.getLocalRegistrationId(),
                userDeviceId,
                signalStore,
                preKeyId,
                signedPreKeyId
            );

            PreKeyBundleDTO dto = PreKeyBundleDTO.fromPreKeyBundle(myBundle);

            Packet preKeyPacket = new Packet(userId, userDeviceId, dto);
            connection.sendMessageObject(preKeyPacket);

            logger.info("[{}] Registered PreKeyBundle with server", userId);

            startListening();
        } catch (Exception e) {
            logger.error("[{}] Failed to connect to server or register PreKeyBundle", userId, e);
            throw e;
        }
    }

    public void establishSession(String peerId, int peerDeviceId) {
        String peerKey = peerId + ":" + peerDeviceId;
        logger.info("[{}] Establishing session with peer {}", userId, peerKey);

        if (peerDeviceId <= 0) {
            logger.error("[{}] Invalid peerDeviceId {} for peer {}", userId, peerDeviceId, peerId);
            return;
        }

        SignalProtocolAddress peerAddress = new SignalProtocolAddress(peerId, peerDeviceId);

        fetchPreKeyBundle(peerId, peerDeviceId).thenAccept(bundle -> {
            try {
                SessionBuilder sessionBuilder = new SessionBuilder(signalStore, peerAddress);
                sessionBuilder.process(bundle);
                logger.info("[{}] Session established with peer {}", userId, peerKey);

                // After session is established, send initial prekey message
                sendPreKeyMessage(peerId, peerDeviceId, "Hello from " + userId);
            } catch (Exception e) {
                logger.error("[{}] Failed to establish session with {}: {}", userId, peerKey, e.getMessage(), e);
            }
        }).exceptionally(e -> {
            logger.error("[{}] Failed to fetch PreKeyBundle for {}: {}", userId, peerKey, e.getMessage(), e);
            return null;
        });
    }

    private CompletableFuture<PreKeyBundle> fetchPreKeyBundle(String peerId, int peerDeviceId) {
        String key = peerId + ":" + PacketType.PREKEY_BUNDLE.name();
        CompletableFuture<Packet> future = new CompletableFuture<>();
        pendingRequests.put(key, future);

        Packet request = new Packet(userId, userDeviceId, peerId, peerDeviceId);
        try {
            connection.sendMessageObject(request);
            logger.info("[{}] Requested PreKeyBundle for peer {}:{}", userId, peerId, peerDeviceId);
        } catch (Exception e) {
            pendingRequests.remove(key);
            future.completeExceptionally(e);
            logger.error("[{}] Failed to send PreKeyBundle request to {}:{} ", userId, peerId, peerDeviceId, e);
        }

        return future.thenApply(packet -> {
            PreKeyBundleDTO dto = packet.getPreKeyBundlePayload();
            return dto.toPreKeyBundle();
        });
    }

    private void sendPreKeyMessage(String peerId, int peerDeviceId, String message) {
        String peerKey = peerId + ":" + peerDeviceId;
        try {
            byte[] encrypted = SPManager.encryptPreKeyMessage(peerId, peerDeviceId, message);
            Packet packet = new Packet(userId, userDeviceId, peerId, peerDeviceId, encrypted, PacketType.PREKEY_MESSAGE);
            connection.sendMessageObject(packet);
            logger.info("[{}] Sent PreKeyMessage to {}", userId, peerKey);
        } catch (Exception e) {
            logger.error("[{}] Failed to send PreKeyMessage to {}: {}", userId, peerKey, e.getMessage(), e);
        }
    }

    public void sendMessage(String peerId, int peerDeviceId, String message) {
        try {
            boolean hasSession = SPManager.hasSession(peerId, peerDeviceId);
            byte[] ciphertext;
            PacketType packetType;
            if (!hasSession) {
                ciphertext = SPManager.encryptPreKeyMessage(peerId, peerDeviceId, message);
                packetType = PacketType.PREKEY_MESSAGE;
            } else {
                ciphertext = SPManager.encryptMessage(peerId, peerDeviceId, message);
                packetType = PacketType.MESSAGE;
            }
            Packet packet = new Packet(userId, userDeviceId, peerId, peerDeviceId, ciphertext, packetType);
            connection.sendMessageObject(packet);
            logger.info("[{}] Sent {} to {} ({} bytes)", userId, packetType, peerId, ciphertext.length);
        } catch (Exception e) {
            logger.error("[{}] Failed to send message to {}: {}", userId, peerId, e.getMessage(), e);
        }
    }

    private void startListening() {
        logger.info("[{}] Starting to listen for incoming packets", userId);
        pool.submit(() -> {
            try {
                while (!Thread.currentThread().isInterrupted()) {
                    Object received = connection.receiveMessageObject();
                    if (received instanceof Packet packet) {
                        handleIncomingPacket(packet);
                    } else {
                        logger.warn("[{}] Received unknown object of type {}: {}", userId,
                                    received == null ? "null" : received.getClass().getName(), received);
                    }
                }
            } catch (IOException | ClassNotFoundException e) {
                logger.error("[{}] Listening stopped due to error", userId, e);
            }
        });
    }

    private void handleIncomingPacket(Packet packet) {
        String senderId = packet.getSenderId();
        int senderDeviceId = packet.getSenderDeviceId();
        String senderKey = senderId + ":" + senderDeviceId;

        try {
            switch (packet.getType()) {
                case PREKEY_BUNDLE -> {
                    String key = senderId + ":" + PacketType.PREKEY_BUNDLE.name();
                    CompletableFuture<Packet> future = pendingRequests.remove(key);
                    if (future != null) {
                        future.complete(packet);
                        logger.info("[{}] Received PREKEY_BUNDLE from {}", userId, senderKey);
                    } else {
                        logger.warn("[{}] No pending request for PREKEY_BUNDLE from {}", userId, senderKey);
                    }
                }
                case PREKEY_MESSAGE -> {
                    SignalProtocolAddress senderAddress = new SignalProtocolAddress(senderId, senderDeviceId);
                    String plaintext = SPManager.decryptPreKeyMessage(senderAddress, packet.getMessagePayload());
                    logger.info("[{}] Received PREKEY_MESSAGE from {}: {}", userId, senderKey, plaintext);

                    // ACK back
                    Packet ack = new Packet(userId, userDeviceId, senderId, senderDeviceId, null, PacketType.ACK);
                    connection.sendMessageObject(ack);
                    logger.info("[{}] Sent ACK to {}", userId, senderKey);
                }
                case MESSAGE -> {
                    if (!SPManager.hasSession(senderId, senderDeviceId)) {
                        logger.warn("[{}] Received MESSAGE from {} without session, ignoring", userId, senderKey);
                        return;
                    }
                    String plaintext = SPManager.decryptMessage(senderId, senderDeviceId, packet.getMessagePayload());
                    logger.info("[{}] Received MESSAGE from {}: {}", userId, senderKey, plaintext);
                }
                case ACK -> {
                    logger.info("[{}] Received ACK from {}", userId, senderKey);
                }
                default -> logger.warn("[{}] Unhandled packet type {} from {}", userId, packet.getType(), senderKey);
            }
        } catch (Exception e) {
            logger.error("[{}] Error processing packet from {}: {}", userId, senderKey, e.getMessage(), e);
        }
    }

    public void stop() {
        logger.info("[{}] Stopping client", userId);
        try {
            if (connection != null) {
                connection.close();
            }
        } catch (IOException e) {
            logger.error("[{}] Error closing connection", userId, e);
        }
        pool.shutdownNow();
        try {
            if (!pool.awaitTermination(5, TimeUnit.SECONDS)) {
                logger.warn("[{}] Executor pool did not shut down cleanly", userId);
            }
        } catch (InterruptedException e) {
            logger.error("[{}] Interrupted while shutting down executor pool", userId, e);
            Thread.currentThread().interrupt();
        }
    }
}
