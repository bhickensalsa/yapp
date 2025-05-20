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

/**
 * Handles the establishment and management of secure Signal Protocol sessions
 * with remote peers. Responsible for requesting PreKey bundles, building sessions,
 * sending encrypted messages, and delegating encryption/decryption to the
 * {@link SignalProtocolManager}.
 * <p>
 * Integrates with the networking layer to request remote cryptographic materials
 * and transmit messages securely.
 *
 * @author bhickensalsa
 * @version 0.1
 */
public class SessionManager {
    private static final Logger logger = LoggerFactory.getLogger(SessionManager.class);

    private final String userId;
    private final int userDeviceId;
    private final SignalProtocolManager SPManager;
    private final PeerConnection connection;
    private final Map<String, CompletableFuture<Packet>> pendingRequests;

    /**
     * Constructs a new SessionManager instance.
     *
     * @param userId           the user ID of the local user
     * @param userDeviceId     the device ID of the local user
     * @param SPManager        the SignalProtocolManager instance to handle encryption tasks
     * @param connection       the network connection to communicate with peers
     * @param pendingRequests  a shared map of pending asynchronous requests keyed by request type
     */
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

    /**
     * Establishes a secure session with a remote peer by fetching their PreKey bundle,
     * initializing the session, and sending the first encrypted PreKey message.
     *
     * @param peerId         the ID of the remote peer
     * @param peerDeviceId   the device ID of the remote peer
     * @param initialMessage the message to send once the session is established
     */
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

    /**
     * Fetches the PreKey bundle from a remote peer using the connection layer.
     * The bundle is returned asynchronously as a {@link CompletableFuture}.
     *
     * @param peerId       the ID of the peer
     * @param peerDeviceId the device ID of the peer
     * @return a future that completes with the peer's PreKey bundle
     */
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
            pendingRequests.remove(key);
            PreKeyBundleDTO dto = packet.getPreKeyBundlePayload();
            return dto.toPreKeyBundle();
        });
    }

    /**
     * Sends an encrypted PreKey message to the specified peer.
     * This is typically used as the first message after session establishment.
     *
     * @param peerId      the ID of the recipient peer
     * @param peerDeviceId the device ID of the recipient peer
     * @param message     the plaintext message to encrypt and send
     */
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

    /**
     * Checks if a session already exists with the given peer and device.
     *
     * @param peerId       the peer's user ID
     * @param peerDeviceId the peer's device ID
     * @return true if a session exists, false otherwise
     */
    public boolean hasSession(String peerId, int peerDeviceId) {
        return SPManager.hasSession(peerId, peerDeviceId);
    }

    /**
     * Decrypts a PreKey message from a peer.
     *
     * @param peerId       the sender's user ID
     * @param peerDeviceId the sender's device ID
     * @param ciphertext   the encrypted PreKey message
     * @return the plaintext message
     * @throws Exception if decryption fails or session is not available
     */
    public String decryptPreKeyMessage(String peerId, int peerDeviceId, byte[] ciphertext) throws Exception {
        return SPManager.decryptPreKeyMessage(peerId, peerDeviceId, ciphertext);
    }

    /**
     * Decrypts a regular Signal message from a peer.
     *
     * @param peerId       the sender's user ID
     * @param peerDeviceId the sender's device ID
     * @param ciphertext   the encrypted Signal message
     * @return the plaintext message
     * @throws Exception if decryption fails or session is not available
     */
    public String decryptMessage(String peerId, int peerDeviceId, byte[] ciphertext) throws Exception {
        return SPManager.decryptMessage(peerId, peerDeviceId, ciphertext);
    }

    /**
     * Encrypts a message for a peer using an existing session.
     *
     * @param peerId       the recipient's user ID
     * @param peerDeviceId the recipient's device ID
     * @param plaintext    the plaintext message to encrypt
     * @return the encrypted message as a byte array
     * @throws Exception if encryption fails or session does not exist
     */
    public byte[] encryptMessage(String peerId, int peerDeviceId, String plaintext) throws Exception {
        return SPManager.encryptMessage(peerId, peerDeviceId, plaintext);
    }
}
