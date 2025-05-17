package com.securechat;

import com.securechat.client.UserClient;
import com.securechat.crypto.KeyManager;
import com.securechat.crypto.libsignal.SignalKeyStore;
import com.securechat.server.Server;
import com.securechat.store.InMemoryPreKeyStore;
import com.securechat.store.PreKeyStore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Launcher {

    private static final Logger logger = LoggerFactory.getLogger(Launcher.class);

    private static final int SERVER_SIGNED_PREKEY_ID = 1;
    private static final int SERVER_PREKEY_ID = 1;

    private static final int MESSAGE_PORT = 8888;
    private static final int PREKEY_PORT = 9999;

    public static void main(String[] args) {

        // === Device & Key IDs ===
        int alicePreKeyId = 1001;
        int aliceSignedPreKeyId = 1002;
        int aliceDeviceId = 1;

        int bobPreKeyId = 2001;
        int bobSignedPreKeyId = 2002;
        int bobDeviceId = 1;

        logger.info("Initializing key stores and preKey store");

        // === Server State ===
        PreKeyStore preKeyStore = new InMemoryPreKeyStore();
        SignalKeyStore serverKeyStore = new SignalKeyStore();
        initializeKeys(serverKeyStore);

        // === Clients' State ===
        SignalKeyStore aliceKeyStore = new SignalKeyStore();
        initializeKeys(aliceKeyStore, alicePreKeyId, aliceSignedPreKeyId);

        SignalKeyStore bobKeyStore = new SignalKeyStore();
        initializeKeys(bobKeyStore, bobPreKeyId, bobSignedPreKeyId);

        // === Start Server ===
        Server server = new Server(MESSAGE_PORT, PREKEY_PORT, serverKeyStore, preKeyStore);
        Thread serverThread = new Thread(server::start, "ServerThread");
        serverThread.start();
        logger.info("Server started on ports {} (messages) and {} (prekeys)", MESSAGE_PORT, PREKEY_PORT);

        waitMillis(1500); // Ensure server is ready

        // === Start Clients ===
        UserClient bob = new UserClient("bob", bobDeviceId, bobKeyStore, bobPreKeyId, bobSignedPreKeyId);
        bob.connectToServer("localhost", MESSAGE_PORT, PREKEY_PORT);
        bob.listen();

        UserClient alice = new UserClient("alice", aliceDeviceId, aliceKeyStore, alicePreKeyId, aliceSignedPreKeyId);
        alice.connectToServer("localhost", MESSAGE_PORT, PREKEY_PORT);
        alice.listen();

        alice.addPeerDeviceId("bob", bobDeviceId);
        bob.addPeerDeviceId("alice", aliceDeviceId);

        waitMillis(1000); // Allow time for prekey bundles to be registered

        // === Session Establishment ===
        alice.establishSessionWith("bob");
        bob.establishSessionWith("alice");

        waitMillis(1000);

        // === Exchange Messages ===
        alice.sendMessage("bob", "Hi Bob!");
        bob.sendMessage("alice", "Hi Alice!");

        waitMillis(1000);

        alice.sendMessage("bob", "Are you available for a call?");
        bob.sendMessage("alice", "Sure, let's do it!");

        // === Keep Main Thread Alive ===
        try {
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            logger.error("Main thread interrupted, shutting down", e);
            Thread.currentThread().interrupt();
        }
    }

    private static void initializeKeys(SignalKeyStore keyStore, int preKeyId, int signedPreKeyId) {
        KeyManager keyManager = new KeyManager();

        var preKey = keyManager.generatePreKey(preKeyId);
        keyStore.storePreKey(preKeyId, preKey);

        var signedPreKey = keyManager.generateSignedPreKey(keyStore.getIdentityKeyPair(), signedPreKeyId);
        keyStore.storeSignedPreKey(signedPreKeyId, signedPreKey);

        logger.debug("Initialized keys: preKeyId={}, signedPreKeyId={}", preKeyId, signedPreKeyId);
    }

    private static void initializeKeys(SignalKeyStore keyStore) {
        initializeKeys(keyStore, SERVER_PREKEY_ID, SERVER_SIGNED_PREKEY_ID);
    }

    private static void waitMillis(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            logger.error("Sleep interrupted", e);
            Thread.currentThread().interrupt();
        }
    }
}
