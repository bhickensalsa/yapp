package com.securechat.crypto.libsignal;

import com.securechat.network.PeerConnection;
import com.securechat.protocol.Packet;
import com.securechat.protocol.PacketType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.SessionBuilder;
import org.whispersystems.libsignal.state.PreKeyBundle;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

public class SessionManager {
    private static final Logger logger = LoggerFactory.getLogger(SessionManager.class);

    private final String userId;
    private final int userDeviceId;
    private final SignalProtocolManager SPManager;
    private final PeerConnection connection;
    private final Map<String, CompletableFuture<Packet>> pendingRequests;

    public SessionManager(String userId, int userDeviceId,
                          SignalProtocolManager SPManager,
                          PeerConnection connection,
                          Map<String, CompletableFuture<Packet>> pendingRequests) {
        this.userId = userId;
        this.userDeviceId = userDeviceId;
        this.SPManager = SPManager;
        this.connection = connection;
        this.pendingRequests = pendingRequests;
    }

    public void establishSession(String peerId, int peerDeviceId, String initialMessage) {
        final String peerKey = peerId + ":" + peerDeviceId;
        logger.info("[{}] Initiating session with {}", userId, peerKey);

        if (peerDeviceId <= 0) {
            logger.error("[{}] Invalid peerDeviceId for {}", userId, peerKey);
            return;
        }

        SignalProtocolAddress peerAddress = new SignalProtocolAddress(peerId, peerDeviceId);

        fetchPreKeyBundle(peerId, peerDeviceId)
            .thenAccept(bundle -> {
                try {
                    new SessionBuilder(SPManager.getStore(), peerAddress).process(bundle);
                    logger.info("[{}] Session successfully established with {}", userId, peerKey);
                    sendPreKeyMessage(peerId, peerDeviceId, initialMessage);
                } catch (Exception e) {
                    logger.error("[{}] Failed to build session with {}: {}", userId, peerKey, e.getMessage(), e);
                }
            })
            .exceptionally(e -> {
                logger.error("[{}] Error fetching PreKeyBundle for {}: {}", userId, peerKey, e.getMessage(), e);
                return null;
            });
    }

    private CompletableFuture<PreKeyBundle> fetchPreKeyBundle(String peerId, int peerDeviceId) {
        final String key = peerId + ":" + PacketType.PREKEY_BUNDLE.name();
        final CompletableFuture<Packet> responseFuture = new CompletableFuture<>();
        pendingRequests.put(key, responseFuture);

        try {
            Packet request = new Packet(userId, userDeviceId, peerId, peerDeviceId);
            connection.sendMessageObject(request);
            logger.info("[{}] Sent PREKEY_BUNDLE request to {}:{}", userId, peerId, peerDeviceId);
        } catch (Exception e) {
            pendingRequests.remove(key);
            responseFuture.completeExceptionally(e);
            logger.error("[{}] Failed to send PREKEY_BUNDLE request to {}:{}", userId, peerId, peerDeviceId, e);
        }

        return responseFuture.thenApply(packet -> {
            pendingRequests.remove(key); // Clean up to avoid leaks
            PreKeyBundleDTO dto = packet.getPreKeyBundlePayload();
            return dto.toPreKeyBundle();
        });
    }

    private void sendPreKeyMessage(String peerId, int peerDeviceId, String message) {
        try {
            byte[] encrypted = SPManager.encryptPreKeyMessage(peerId, peerDeviceId, message);
            Packet packet = new Packet(userId, userDeviceId, peerId, peerDeviceId, encrypted, PacketType.PREKEY_MESSAGE);
            connection.sendMessageObject(packet);
            logger.info("[{}] Sent PREKEY_MESSAGE to {}:{}", userId, peerId, peerDeviceId);
        } catch (Exception e) {
            logger.error("[{}] Failed to send PREKEY_MESSAGE to {}:{} - {}", userId, peerId, peerDeviceId, e.getMessage(), e);
        }
    }

    public boolean hasSession(String peerId, int peerDeviceId) {
        return SPManager.hasSession(peerId, peerDeviceId);
    }

    public String decryptPreKeyMessage(String peerId, int peerDeviceId, byte[] ciphertext) throws Exception {
        return SPManager.decryptPreKeyMessage(peerId, peerDeviceId, ciphertext);
    }

    public String decryptMessage(String peerId, int peerDeviceId, byte[] ciphertext) throws Exception {
        return SPManager.decryptMessage(peerId, peerDeviceId, ciphertext);
    }

    public byte[] encryptMessage(String peerId, int peerDeviceId, String plaintext) throws Exception {
        return SPManager.encryptMessage(peerId, peerDeviceId, plaintext);
    }
}
