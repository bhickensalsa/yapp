package com.securechat.client;

import com.securechat.crypto.libsignal.SignalProtocolManager;
import com.securechat.crypto.libsignal.PreKeyBundleBuilder;
import com.securechat.crypto.libsignal.PreKeyBundleDTO;
import com.securechat.crypto.libsignal.SignalKeyStore;
import com.securechat.network.PeerConnection;
import com.securechat.protocol.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.state.PreKeyBundle;

import java.net.Socket;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class UserClient {
    private static final Logger logger = LoggerFactory.getLogger(UserClient.class);

    private final String userId;
    private final int deviceId;
    private final SignalKeyStore keyStore;
    private final SignalProtocolManager cryptoManager;

    private final int preKeyId;
    private final int signedPreKeyId;

    private PeerConnection connection;
    private PreKeyBundle myBundle;

    private final Map<String, Integer> peerDeviceIds = new ConcurrentHashMap<>();

    private final ExecutorService pool = Executors.newCachedThreadPool();

    public UserClient(String userId, int deviceId, SignalKeyStore keyStore, int preKeyId, int signedPreKeyId) {
        this.userId = userId;
        this.deviceId = deviceId;
        this.keyStore = keyStore;
        this.cryptoManager = new SignalProtocolManager(keyStore);
        this.preKeyId = preKeyId;
        this.signedPreKeyId = signedPreKeyId;
    }

    public void connectToServer(String host, int messagePort, int preKeyPort) {
        try {
            Socket messageSocket = new Socket(host, messagePort);
            Socket preKeySocket = new Socket(host, preKeyPort);
            this.connection = new PeerConnection(messageSocket, preKeySocket);

            // Send userId on message socket
            connection.sendMessageObject(userId);

            // Build and send PreKeyBundle on preKey socket
            myBundle = PreKeyBundleBuilder.build(
                    keyStore.getLocalRegistrationId(), deviceId,
                    keyStore, preKeyId, signedPreKeyId
            );
            PreKeyBundleDTO dto = PreKeyBundleDTO.fromPreKeyBundle(myBundle);

            connection.sendPreKeyObject(new Packet(userId, dto));

            logger.info("Registered prekey bundle with server as '{}'", userId);
        } catch (Exception e) {
            logger.error("Connection or registration failed: {}", e.getMessage(), e);
        }
    }

    public boolean establishSessionWith(String peerId) {
        try {
            int peerDeviceId = peerDeviceIds.getOrDefault(peerId, deviceId);
            SignalProtocolAddress peerAddress = new SignalProtocolAddress(peerId, peerDeviceId);

            if (cryptoManager.hasSession(peerId, peerDeviceId)) {
                logger.info("Session with {} already exists", peerId);
                return true;
            }

            // Request peer's prekey bundle from server via preKey socket
            connection.sendPreKeyObject(new Packet(userId, PacketType.GET_PREKEY_BUNDLE, peerId));
            Object obj = connection.receivePreKeyObject();

            if (!(obj instanceof Packet response)) {
                logger.warn("Unexpected response on prekey stream: {}", obj);
                return false;
            }

            if (response.getType() == PacketType.PREKEY_BUNDLE) {
                PreKeyBundleDTO dto = response.getPreKeyBundlePayload();
                if (dto == null) {
                    logger.warn("PREKEY_BUNDLE packet missing payload");
                    return false;
                }

                PreKeyBundle bundle = dto.toPreKeyBundle();

                PreKeySignalMessage preKeySignalMessage = cryptoManager.buildInitialPreKeyMessage(peerAddress, bundle, "Hello from " + userId);
                if (preKeySignalMessage != null) {
                    byte[] serializedMessage = preKeySignalMessage.serialize();
                    Packet packet = new Packet(PacketType.PREKEY_MESSAGE, serializedMessage, userId, peerId);
                    sendPacket(packet);

                    cryptoManager.initializeSession(peerAddress, bundle);

                    logger.info("Sent initial PREKEY message and initialized session with {}", peerId);
                    return true;
                } else {
                    logger.error("Failed to build initial PREKEY message for {}", peerId);
                    return false;
                }
            }

            if (response.getType() == PacketType.ERROR) {
                String errorMessage = response.getStringPayload();
                logger.error("PreKey error from server: {}", errorMessage);
            } else {
                logger.warn("Unexpected packet type during session setup: {}", response.getType());
            }
        } catch (Exception e) {
            logger.error("Failed to establish session with {}: {}", peerId, e.getMessage(), e);
        }
        return false;
    }

    public boolean sendMessage(String recipientId, String plaintext) {
        Integer peerDeviceId = peerDeviceIds.get(recipientId);
        if (peerDeviceId == null) {
            logger.warn("No device ID found for recipient {}, cannot send message", recipientId);
            return false;
        }

        try {
            SignalProtocolAddress recipientAddress = new SignalProtocolAddress(recipientId, peerDeviceId);

            if (!cryptoManager.hasSession(recipientId, peerDeviceId)) {
                logger.warn("No session established with {}, cannot encrypt message", recipientId);
                return false;
            }

            SignalMessage encryptedSignalMessage = cryptoManager.encryptMessage(recipientAddress, plaintext);
            if (encryptedSignalMessage == null) {
                logger.error("Encryption returned null for recipient {}", recipientId);
                return false;
            }

            byte[] serializedMessage = encryptedSignalMessage.serialize();

            Packet encryptedPacket = new Packet(PacketType.MESSAGE, serializedMessage, userId, recipientId);
            sendPacket(encryptedPacket);

            logger.info("Sent encrypted message to {}", recipientId);
            return true;

        } catch (Exception e) {
            logger.error("Failed to send message to {}: {}", recipientId, e.getMessage(), e);
            return false;
        }
    }

    private void sendPacket(Packet packet) throws Exception {
        if (connection == null) throw new IllegalStateException("Not connected");
        connection.sendMessageObject(packet);
    }

    public void listen() {
        pool.execute(() -> {
            try {
                while (true) {
                    Object obj = connection.receiveMessageObject();

                    if (!(obj instanceof Packet packet)) {
                        logger.warn("Invalid object received: {}", obj);
                        continue;
                    }

                    switch (packet.getType()) {
                        case PREKEY_MESSAGE -> handlePreKeyMessage(packet);
                        case MESSAGE -> handleMessage(packet);
                        default -> logger.debug("Ignoring packet of type {}", packet.getType());
                    }
                }
            } catch (Exception e) {
                logger.error("Listener stopped due to exception: {}", e.getMessage(), e);
            }
        });
    }

    private void handlePreKeyMessage(Packet packet) {
        byte[] bytes = packet.getMessagePayload();
        if (bytes == null) {
            logger.warn("PREKEY_MESSAGE packet has null payload");
            return;
        }

        Integer deviceId = peerDeviceIds.get(packet.getSender());
        if (deviceId == null) {
            logger.warn("Unknown deviceId for sender {}", packet.getSender());
            return;
        }

        SignalProtocolAddress senderAddress = new SignalProtocolAddress(packet.getSender(), deviceId);

        try {
            PreKeySignalMessage preKeySignalMessage = new PreKeySignalMessage(bytes);
            String plaintext = cryptoManager.decryptPreKeyMessage(senderAddress, preKeySignalMessage);
            if (plaintext != null) {
                logger.info("Decrypted PREKEY message: {}", plaintext);
                // TODO: handle decrypted plaintext
            } else {
                logger.warn("Failed to decrypt PREKEY message from {}", packet.getSender());
            }
        } catch (Exception e) {
            logger.warn("Failed to parse PreKeySignalMessage from bytes: {}", e.getMessage());
        }
    }

    private void handleMessage(Packet packet) {
        byte[] bytes = packet.getMessagePayload();
        if (bytes == null) {
            logger.warn("MESSAGE packet has null payload");
            return;
        }

        Integer deviceId = peerDeviceIds.get(packet.getSender());
        if (deviceId == null) {
            logger.warn("Unknown deviceId for sender {}", packet.getSender());
            return;
        }

        SignalProtocolAddress senderAddress = new SignalProtocolAddress(packet.getSender(), deviceId);

        try {
            SignalMessage signalMessage = new SignalMessage(bytes);
            String plaintext = cryptoManager.decryptMessage(senderAddress, signalMessage);
            if (plaintext != null) {
                logger.info("Decrypted message: {}", plaintext);
                // TODO: handle decrypted plaintext
            } else {
                logger.warn("Failed to decrypt message from {}", packet.getSender());
            }
        } catch (Exception e) {
            logger.warn("Failed to parse SignalMessage from bytes: {}", e.getMessage());
        }
    }

    public void disconnect() {
        try {
            if (connection != null) {
                connection.close();
                logger.info("Disconnected from server");
            }
            pool.shutdownNow();
        } catch (Exception e) {
            logger.warn("Error while disconnecting: {}", e.getMessage(), e);
        }
    }

    public void addPeerDeviceId(String peerId, int deviceId) {
        peerDeviceIds.put(peerId, deviceId);
    }
}
