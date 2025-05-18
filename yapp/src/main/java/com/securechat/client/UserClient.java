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
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.KeyHelper;

import java.io.IOException;
import java.net.Socket;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
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
    
    private int recipientDeviceId;
    private PeerConnection connection;
    private PreKeyBundle myBundle;

    private final Map<String, Integer> peerDeviceIds = new ConcurrentHashMap<>();
    private final ExecutorService pool = Executors.newCachedThreadPool();

    private final Map<String, CompletableFuture<Packet>> pendingRequests = new ConcurrentHashMap<>();

    public UserClient(String userId, int userDeviceId, SignalStore signalStore, int preKeyId, int signedPreKeyId) {
        this.userId = userId;
        this.userDeviceId = userDeviceId;
        this.signalStore = signalStore;
        this.SPManager = new SignalProtocolManager(signalStore);
        this.preKeyId = preKeyId;
        this.signedPreKeyId = signedPreKeyId;
    }

    public void initializeUser() {
        try {
            // Generate keys
            IdentityKeyPair identityKeyPair = KeyHelper.generateIdentityKeyPair();
            int registrationId = KeyHelper.generateRegistrationId(false);

            signalStore.initializeKeys(identityKeyPair, registrationId);

            PreKeyRecord preKey = KeyHelper.generatePreKeys(preKeyId, 1).get(0);
            SignedPreKeyRecord signedPreKey = KeyHelper.generateSignedPreKey(identityKeyPair, signedPreKeyId);

            signalStore.storePreKey(preKeyId, preKey);
            signalStore.storeSignedPreKey(signedPreKeyId, signedPreKey);

            logger.info("User initialized with IdentityKeyPair, PreKey ID {}, and SignedPreKey ID {}", preKeyId, signedPreKeyId);
        } catch (Exception e) {
            logger.error("Failed to initialize user keys: {}", e.getMessage(), e);
        }
    }

    public void connectToServer(String host, int port) {
        try {
            logger.info("Connecting to server at {}:{}", host, port);
            Socket socket = new Socket(host, port);
            this.connection = new PeerConnection(socket);

            this.myBundle = PreKeyBundleBuilder.build(
                    signalStore.getLocalRegistrationId(),
                    userDeviceId,
                    signalStore,
                    preKeyId,
                    signedPreKeyId
            );

            PreKeyBundleDTO dto = PreKeyBundleDTO.fromPreKeyBundle(myBundle);

            Packet preKeyPacket = new Packet(userId, userDeviceId, "server", 0, dto);

            connection.sendMessageObject(preKeyPacket);

            logger.info("Successfully registered PreKeyBundle with server as '{}'", userId);
        } catch (Exception e) {
            logger.error("Failed to connect or register with server: {}", e.getMessage(), e);
        }
        startListening();
    }
    
    public void establishSession(String peerId, int peerDeviceId) {
        if (peerDeviceId == 0) {
            logger.error("Invalid device ID 0 for peer '{}'. Cannot establish session.", peerId);
            return;
        }

        fetchPreKeyBundle(peerId, peerDeviceId).thenAccept(bundle -> {
            try {
                recipientDeviceId = bundle.getDeviceId();
                SPManager.initializeSession(peerId, bundle);
                logger.info("Session successfully established with {}", peerId);
                sendPreKeyMessage(peerId, "Hello from " + userId + "!");
            } catch (Exception e) {
                logger.error("Failed to establish session with {}: {}", peerId, e.getMessage(), e);
            }
        }).exceptionally(e -> {
            logger.error("Failed to fetch prekey bundle for {}: {}", peerId, e.getMessage());
            return null;
        });
    }

    public CompletableFuture<PreKeyBundle> fetchPreKeyBundle(String peerId, int peerDeviceId) {
        String pendingKey = peerId + ":" + PacketType.PREKEY_BUNDLE.name();

        CompletableFuture<Packet> responseFuture = new CompletableFuture<>();
        pendingRequests.put(pendingKey, responseFuture);

        Packet requestPacket = new Packet(userId, userDeviceId, peerId, peerDeviceId);

        try {
            connection.sendMessageObject(requestPacket);
            logger.info("Requested prekey bundle for peer '{}'", peerId);
        } catch (Exception e) {
            logger.error("Failed to send GET_PREKEY_BUNDLE for '{}': {}", peerId, e.getMessage());
            pendingRequests.remove(pendingKey);
            responseFuture.completeExceptionally(e);
        }

        return responseFuture.thenApply(packet -> {
            PreKeyBundleDTO dto = packet.getPreKeyBundlePayload();
            return dto.toPreKeyBundle();
        });
    }


    private void sendPreKeyMessage(String recipientId, String message) {
        try {
            byte[] encrypted = SPManager.encryptPreKeyMessage(recipientId, recipientDeviceId, message);
            Packet packet = new Packet(userId, userDeviceId, recipientId, recipientDeviceId, encrypted, PacketType.PREKEY_MESSAGE);
            connection.sendMessageObject(packet);
            logger.info("Sent PreKeyMessage to {}", recipientId);
        } catch (Exception e) {
            logger.error("Failed to send PreKeyMessage to {}: {}", recipientId, e.getMessage(), e);
        }
    }

    public void sendMessage(String recipientId, String message) {
        try {
            boolean hasSession = SPManager.hasSession(recipientId, recipientDeviceId);

            byte[] ciphertext;
            PacketType packetType;

            if (!hasSession) {
                ciphertext = SPManager.encryptPreKeyMessage(recipientId, recipientDeviceId, message);
                packetType = PacketType.PREKEY_MESSAGE;
            } else {
                ciphertext = SPManager.encryptMessage(recipientId, recipientDeviceId, message);
                packetType = PacketType.MESSAGE;
            }

            Packet packet = new Packet(userId, userDeviceId, recipientId, recipientDeviceId, ciphertext, packetType);
            connection.sendMessageObject(packet);

            logger.info("Sent {} to {} ({} bytes)", packetType, recipientId, ciphertext.length);

        } catch (Exception e) {
            logger.error("Failed to send message to {}: {}", recipientId, e.getMessage(), e);
        }
    }

    public void startListening() {
        pool.submit(() -> {
            try {
                while (!Thread.currentThread().isInterrupted()) {
                    Object received = connection.receiveMessageObject();
                    if (received instanceof Packet packet) {
                        handleIncomingPacket(packet);
                    } else {
                        logger.warn("Received unknown object: {}", received);
                    }
                }
            } catch (IOException | ClassNotFoundException e) {
                logger.error("Connection lost or error during listening: {}", e.getMessage(), e);
            }
        });
    }

    private void handleIncomingPacket(Packet packet) {
        String senderId = packet.getSenderId();
        int senderDeviceId = packet.getSenderDeviceId();

        try {
            switch (packet.getType()) {
                case PREKEY_BUNDLE:
                    String key = senderId + ":" + PacketType.PREKEY_BUNDLE.name();
                    CompletableFuture<Packet> future = pendingRequests.remove(key);
                    if (future != null) {
                        future.complete(packet);
                        return; // no further processing needed here
                    }
                    break;

                case PREKEY_MESSAGE:
                    try {
                        String plaintext = SPManager.decryptPreKeyMessage(senderId, senderDeviceId, packet.getMessagePayload());
                        logger.info("Received from {} (device {}): {}", senderId, senderDeviceId, plaintext);
                    } catch (Exception e) {
                        logger.error("Failed to decrypt PreKeyMessage from {}: {}", senderId, e.getMessage(), e);
                    }
                    break;

                case MESSAGE:
                    if (!SPManager.hasSession(senderId, senderDeviceId)) {
                        logger.warn("Received encrypted message from {} but no session exists, ignoring.", senderId);
                        return;
                    }
                    String plaintext = SPManager.decryptMessage(senderId, senderDeviceId, packet.getMessagePayload());
                    logger.info("Received from {} (device {}): {}", senderId, senderDeviceId, plaintext);
                    break;

                default:
                    logger.warn("Unhandled packet type: {}", packet.getType());
            }
        } catch (Exception e) {
            logger.error("Error processing incoming packet: {}", e.getMessage(), e);
        }
    }


    // Register a peer with their device ID
    public void addPeerDeviceId(String peerUserId, int deviceId) {
        peerDeviceIds.put(peerUserId, deviceId);
        logger.info("Added peer '{}' with device ID {}", peerUserId, deviceId);
    }

    // Remove a peer and its device ID mapping
    public void removePeerDeviceId(String peerUserId) {
        peerDeviceIds.remove(peerUserId);
        logger.info("Removed peer '{}'", peerUserId);
    }


    public void stop() {
        logger.info("Stopping client '{}'", userId);

        try {
            if (connection != null) {
                connection.close();
            }
        } catch (IOException e) {
            logger.warn("Error closing connection: {}", e.getMessage(), e);
        }

        pool.shutdownNow();
        try {
            if (!pool.awaitTermination(5, TimeUnit.SECONDS)) {
                logger.warn("Executor did not terminate in time.");
            }
        } catch (InterruptedException e) {
            logger.warn("Interrupted while waiting for executor shutdown.");
            Thread.currentThread().interrupt();
        }

        logger.info("Client '{}' stopped.", userId);
    }
}
