package com.securechat.client;

import com.securechat.crypto.libsignal.*;
import com.securechat.network.PeerConnection;
import com.securechat.network.PacketManager;
import com.securechat.protocol.Packet;
import com.securechat.protocol.PacketType;
import com.securechat.store.SignalStore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.util.KeyHelper;
import org.whispersystems.libsignal.state.PreKeyBundle;

import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.*;

public class UserClient {
    private static final Logger logger = LoggerFactory.getLogger(UserClient.class);

    private final String userId;
    private final int userDeviceId;
    private final SignalStore signalStore;
    private final SignalProtocolManager SPManager;

    private final int preKeyId;
    private final int signedPreKeyId;

    private PeerConnection connection;
    private PacketManager packetManager;
    private SessionManager sessionManager;

    private final ConcurrentHashMap<String, CompletableFuture<Packet>> pendingRequests = new ConcurrentHashMap<>();
    private final ExecutorService executor = Executors.newCachedThreadPool();

    public UserClient(String userId, int userDeviceId, SignalStore signalStore, int preKeyId, int signedPreKeyId) {
        this.userId = userId;
        this.userDeviceId = userDeviceId;
        this.signalStore = signalStore;
        this.SPManager = new SignalProtocolManager(signalStore);
        this.preKeyId = preKeyId;
        this.signedPreKeyId = signedPreKeyId;
    }

    public void initializeUser() {
        logger.info("[{}] Initializing keys with PreKeyId={} and SignedPreKeyId={}", userId, preKeyId, signedPreKeyId);
        try {
            IdentityKeyPair identityKeyPair = KeyHelper.generateIdentityKeyPair();
            int registrationId = KeyHelper.generateRegistrationId(false);

            signalStore.initializeKeys(identityKeyPair, registrationId);
            signalStore.storePreKey(preKeyId, KeyHelper.generatePreKeys(preKeyId, 1).get(0));
            signalStore.storeSignedPreKey(signedPreKeyId, KeyHelper.generateSignedPreKey(identityKeyPair, signedPreKeyId));

            logger.info("[{}] Keys initialized successfully", userId);
        } catch (Exception e) {
            logger.error("[{}] Failed to initialize keys", userId, e);
        }
    }

    public void connectToServer(String host, int port) throws IOException {
        logger.info("[{}] Connecting to server at {}:{}", userId, host, port);
        try {
            this.connection = new PeerConnection(new Socket(host, port));
            this.packetManager = new PacketManager(userId, userDeviceId, connection, SPManager, pendingRequests);
            this.sessionManager = new SessionManager(userId, userDeviceId, SPManager, connection, pendingRequests);

            PreKeyBundle bundle = PreKeyBundleBuilder.build(
                signalStore.getLocalRegistrationId(),
                userDeviceId,
                signalStore,
                preKeyId,
                signedPreKeyId
            );

            Packet registrationPacket = new Packet(userId, userDeviceId, PreKeyBundleDTO.fromPreKeyBundle(bundle));
            connection.sendMessageObject(registrationPacket);
            logger.info("[{}] Registered PreKeyBundle with server", userId);

            packetManager.startListening();
        } catch (IOException e) {
            logger.error("[{}] IO error during connection", userId, e);
            throw e;
        } catch (Exception e) {
            logger.error("[{}] Unexpected error during setup", userId, e);
            throw new IOException("Connection setup failed", e);
        }
    }

    public void establishSession(String peerId, int peerDeviceId, String initialMessage) {
        logger.info("[{}] Establishing session with peer {}:{}", userId, peerId, peerDeviceId);
        sessionManager.establishSession(peerId, peerDeviceId, initialMessage);
    }

    public void sendMessage(String peerId, int peerDeviceId, String message) {
        try {
            packetManager.sendMessage(peerId, peerDeviceId, message, PacketType.MESSAGE);
            logger.info("[{}] Sent message to {}:{}", userId, peerId, peerDeviceId);
        } catch (Exception e) {
            logger.error("[{}] Failed to send message to {}:{}", userId, peerId, peerDeviceId, e);
        }
    }

    public void sendAck(String peerId, int peerDeviceId) {
        try {
            packetManager.sendAck(peerId, peerDeviceId);
            logger.info("[{}] Sent ACK to {}:{}", userId, peerId, peerDeviceId);
        } catch (Exception e) {
            logger.error("[{}] Failed to send ACK to {}:{}", userId, peerId, peerDeviceId, e);
        }
    }

    public void stop() {
        logger.info("[{}] Shutting down client...", userId);

        try {
            if (connection != null) {
                connection.close();
                logger.info("[{}] Connection closed", userId);
            }
        } catch (IOException e) {
            logger.error("[{}] Error closing connection", userId, e);
        }

        if (packetManager != null) {
            try {
                packetManager.shutdown();
                logger.info("[{}] PacketManager stopped", userId);
            } catch (Exception e) {
                logger.error("[{}] Error shutting down PacketManager", userId, e);
            }
        }

        executor.shutdownNow();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                logger.warn("[{}] Executor did not shut down cleanly", userId);
            } else {
                logger.info("[{}] Executor shut down", userId);
            }
        } catch (InterruptedException e) {
            logger.error("[{}] Interrupted during shutdown", userId, e);
            Thread.currentThread().interrupt();
        }
    }
}
