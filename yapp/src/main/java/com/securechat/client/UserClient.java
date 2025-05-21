package com.securechat.client;

import com.securechat.crypto.libsignal.*;
import com.securechat.network.PeerConnection;
import com.securechat.network.UserStatusUpdateListener;
import com.securechat.network.PacketManager;
import com.securechat.protocol.Packet;
import com.securechat.protocol.PacketType;
import com.securechat.protocol.dto.PreKeyBundleDTO;
import com.securechat.store.SignalStore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.util.KeyHelper;
import org.whispersystems.libsignal.state.PreKeyBundle;

import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.*;

/**
 * Represents a SecureChat client that manages cryptographic keys, 
 * establishes secure sessions with peers, registers its PreKeyBundle 
 * with the server, and sends encrypted messages.
 * 
 * <p>Handles Signal Protocol integration (X3DH handshake and Double Ratchet),
 * client-server communication, and asynchronous event notifications.
 * 
 * <p>Network communication and encryption/decryption occur client-side.
 * 
 * @author bhickensalsa
 * @version 0.2
 */
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
    private UserStatusUpdateListener statusListener;
    private IncomingMessageListener incomingMessageListener;

    // Tracks pending asynchronous packet requests keyed by message ID
    private final ConcurrentHashMap<String, CompletableFuture<Packet>> pendingRequests = new ConcurrentHashMap<>();

    // Thread pool executor for background async tasks
    private final ExecutorService executor = Executors.newCachedThreadPool();

    /**
     * Functional interface for receiving decrypted messages asynchronously.
     */
    public interface IncomingMessageListener {
        /**
         * Called when a decrypted message is received from a peer.
         * 
         * @param fromUserId The sender's user ID.
         * @param message The decrypted message content.
         */
        void onMessageReceived(String fromUserId, String message);
    }

    /**
     * Constructs a new UserClient for a given user ID and device ID, 
     * with associated cryptographic storage and key identifiers.
     * 
     * @param userId         The user's unique identifier.
     * @param userDeviceId   The device's unique identifier.
     * @param signalStore    Local store for cryptographic keys and sessions.
     * @param preKeyId       PreKey ID for key registration.
     * @param signedPreKeyId SignedPreKey ID for key registration.
     */
    public UserClient(String userId, int userDeviceId, SignalStore signalStore, int preKeyId, int signedPreKeyId) {
        this.userId = userId;
        this.userDeviceId = userDeviceId;
        this.signalStore = signalStore;
        this.SPManager = new SignalProtocolManager(signalStore);
        this.preKeyId = preKeyId;
        this.signedPreKeyId = signedPreKeyId;
    }

    /**
     * Sets the listener for user status updates (e.g., connection or error messages).
     * 
     * @param listener The listener to notify on status changes.
     */
    public void setUserStatusUpdateListener(UserStatusUpdateListener listener) {
        this.statusListener = listener;
    }

    /**
     * Sets the listener for receiving decrypted incoming messages.
     * 
     * @param listener The listener to notify on incoming messages.
     */
    public void setIncomingMessageListener(IncomingMessageListener listener) {
        this.incomingMessageListener = listener;
    }

    /**
     * Notifies the status listener about user status changes.
     * 
     * @param msg The status message to send.
     */
    private void notifyStatusUpdate(String msg) {
        if (statusListener != null) {
            statusListener.onUserStatusUpdate(msg);
        }
    }

    /**
     * Notifies the incoming message listener of a newly received decrypted message.
     * 
     * @param fromUserId The sender's user ID.
     * @param message The decrypted message content.
     */
    private void notifyIncomingMessage(String fromUserId, String message) {
        if (incomingMessageListener != null) {
            incomingMessageListener.onMessageReceived(fromUserId, message);
        }
    }

    /**
     * Initializes the user's cryptographic keys and registers them in the SignalStore.
     * Generates identity key pair, registration ID, prekeys, and signed prekeys.
     */
    public void initializeUser() {
        logger.info("[{}] Initializing cryptographic keys (PreKeyId={}, SignedPreKeyId={})", userId, preKeyId, signedPreKeyId);
        try {
            // Generate identity key pair and registration ID
            IdentityKeyPair identityKeyPair = KeyHelper.generateIdentityKeyPair();
            int registrationId = KeyHelper.generateRegistrationId(false);

            // Initialize keys in local storage
            signalStore.initializeKeys(identityKeyPair, registrationId);

            // Generate and store a PreKey
            signalStore.storePreKey(preKeyId, KeyHelper.generatePreKeys(preKeyId, 1).get(0));

            // Generate and store a SignedPreKey
            signalStore.storeSignedPreKey(signedPreKeyId, KeyHelper.generateSignedPreKey(identityKeyPair, signedPreKeyId));

            logger.info("[{}] Cryptographic keys initialized successfully", userId);
            notifyStatusUpdate("Keys initialized");
        } catch (Exception e) {
            logger.error("[{}] Error initializing cryptographic keys", userId, e);
            notifyStatusUpdate("Failed to initialize keys: " + e.getMessage());
        }
    }

    /**
     * Connects to the SecureChat server at the specified host and port, 
     * registers the client's PreKeyBundle, and starts listening for incoming packets.
     * 
     * @param host Server hostname or IP address.
     * @param port Server port number.
     * @throws IOException If network connection or registration fails.
     */
    public void connectToServer(String host, int port) throws IOException {
        logger.info("[{}] Connecting to server at {}:{}", userId, host, port);
        try {
            // Open socket connection to the server
            this.connection = new PeerConnection(new Socket(host, port));

            // Initialize packet and session managers
            this.packetManager = new PacketManager(userId, userDeviceId, connection, SPManager, pendingRequests);
            this.sessionManager = new SessionManager(userId, userDeviceId, SPManager, connection, pendingRequests);

            // Register listeners for decrypted messages and status updates
            packetManager.setDecryptedMessageListener((fromUser, fromDevice, message) -> {
                logger.info("[{}] Received decrypted message from {}: {}", userId, fromUser, message);
                notifyIncomingMessage(fromUser, message);
            });

            packetManager.setStatusUpdateListener(this::notifyStatusUpdate);

            // Build PreKeyBundle for registration with the server
            PreKeyBundle bundle = PreKeyBundleBuilder.build(
                signalStore.getLocalRegistrationId(),
                userDeviceId,
                signalStore,
                preKeyId,
                signedPreKeyId
            );

            // Send registration packet containing the PreKeyBundle
            Packet registrationPacket = new Packet(userId, userDeviceId, PreKeyBundleDTO.fromPreKeyBundle(bundle));
            connection.sendMessageObject(registrationPacket);

            logger.info("[{}] Registered PreKeyBundle with server", userId);
            notifyStatusUpdate("Registered PreKeyBundle with server");

            // Begin listening for incoming packets asynchronously
            packetManager.startListening();
            notifyStatusUpdate("Listening for incoming packets...");
        } catch (IOException e) {
            logger.error("[{}] IOException during server connection", userId, e);
            throw e;
        } catch (Exception e) {
            logger.error("[{}] Unexpected error during client setup", userId, e);
            throw new IOException("Failed to set up connection", e);
        }
    }

    /**
     * Establishes a secure session with a peer and sends an initial message.
     * Uses Signal Protocol's X3DH handshake to setup session state.
     * 
     * @param peerId         The recipient user's ID.
     * @param peerDeviceId   The recipient device's ID.
     * @param initialMessage The plaintext message to send initially.
     */
    public void establishSession(String peerId, int peerDeviceId, String initialMessage) {
        logger.info("[{}] Establishing secure session with peer {}:{}", userId, peerId, peerDeviceId);
        try {
            sessionManager.establishSession(peerId, peerDeviceId, initialMessage);
            notifyStatusUpdate("Session established with " + peerId + ":" + peerDeviceId);
        } catch (Exception e) {
            logger.error("[{}] Failed to establish session with {}:{}", userId, peerId, peerDeviceId, e);
            notifyStatusUpdate("Session establishment failed: " + e.getMessage());
        }
    }

    /**
     * Sends an encrypted message to a peer over an established secure session.
     * 
     * @param peerId       The recipient user's ID.
     * @param peerDeviceId The recipient device's ID.
     * @param message      The plaintext message to encrypt and send.
     * @param type         The packet type indicating the message nature.
     */
    public void sendMessage(String peerId, int peerDeviceId, String message, PacketType type) {
        try {
            packetManager.sendMessage(peerId, peerDeviceId, message, type);
            logger.info("[{}] Sent message to {}:{}", userId, peerId, peerDeviceId);
            notifyStatusUpdate("Message sent to " + peerId);
        } catch (Exception e) {
            logger.error("[{}] Failed to send message to {}:{}", userId, peerId, peerDeviceId, e);
            notifyStatusUpdate("Failed to send message: " + e.getMessage());
        }
    }

    /**
     * Sends an acknowledgment (ACK) packet to a peer.
     * 
     * @param peerId       The recipient user's ID.
     * @param peerDeviceId The recipient device's ID.
     */
    public void sendAck(String peerId, int peerDeviceId) {
        try {
            packetManager.sendAck(peerId, peerDeviceId);
            logger.info("[{}] Sent ACK to {}:{}", userId, peerId, peerDeviceId);
            notifyStatusUpdate("ACK sent to " + peerId);
        } catch (Exception e) {
            logger.error("[{}] Failed to send ACK to {}:{}", userId, peerId, peerDeviceId, e);
            notifyStatusUpdate("Failed to send ACK: " + e.getMessage());
        }
    }

    /**
     * Stops the client by closing connections, shutting down listeners,
     * and terminating background executor services cleanly.
     */
    public void stop() {
        logger.info("[{}] Shutting down client...", userId);

        // Close the peer connection socket if open
        try {
            if (connection != null) {
                connection.close();
                logger.info("[{}] Connection closed", userId);
            }
        } catch (IOException e) {
            logger.error("[{}] Error closing connection", userId, e);
        }

        // Shutdown PacketManager to stop background network listeners
        if (packetManager != null) {
            try {
                packetManager.shutdown();
                logger.info("[{}] PacketManager stopped", userId);
            } catch (Exception e) {
                logger.error("[{}] Error shutting down PacketManager", userId, e);
            }
        }

        // Shutdown executor service and await termination
        executor.shutdownNow();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                logger.warn("[{}] Executor did not terminate cleanly", userId);
            } else {
                logger.info("[{}] Executor shut down successfully", userId);
            }
        } catch (InterruptedException e) {
            logger.error("[{}] Interrupted during executor shutdown", userId, e);
            Thread.currentThread().interrupt();
        }
    }
}
