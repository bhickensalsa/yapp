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

    // Define separate ports for message and preKey sockets
    private static final int MESSAGE_PORT = 8888;
    private static final int PREKEY_PORT = 9999;

    public static void main(String[] args) {

        int alicePreKeyId = 1001;
        int aliceSignedPreKeyId = 1002;
        int aliceDeviceId = 1;

        int bobPreKeyId = 2001;
        int bobSignedPreKeyId = 2002;
        int bobDeviceId = 2;

        logger.info("Initializing preKeyStore and keyStores");

        PreKeyStore preKeyStore = new InMemoryPreKeyStore();
        SignalKeyStore serverKeyStore = new SignalKeyStore();
        initializeKeys(serverKeyStore);

        SignalKeyStore aliceKeyStore = new SignalKeyStore();
        initializeKeys(aliceKeyStore, alicePreKeyId, aliceSignedPreKeyId);

        SignalKeyStore bobKeyStore = new SignalKeyStore();
        initializeKeys(bobKeyStore, bobPreKeyId, bobSignedPreKeyId);

        // Start the server with both ports for messages and prekeys
        Server server = new Server(MESSAGE_PORT, PREKEY_PORT, serverKeyStore, preKeyStore);
        Thread serverThread = new Thread(server::start, "ServerThread");
        serverThread.start();
        logger.info("Server started on message port {} and prekey port {}", MESSAGE_PORT, PREKEY_PORT);

        // Wait briefly for the server to start
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            logger.error("Main thread interrupted while waiting for server to start", e);
            Thread.currentThread().interrupt();
        }

        // Now connect clients with both ports
        UserClient bob = new UserClient("bob", bobDeviceId, bobKeyStore, bobPreKeyId, bobSignedPreKeyId);
        bob.connectToServer("localhost", MESSAGE_PORT, PREKEY_PORT);
        bob.listen();

        UserClient alice = new UserClient("alice", aliceDeviceId, aliceKeyStore, alicePreKeyId, aliceSignedPreKeyId);
        alice.connectToServer("localhost", MESSAGE_PORT, PREKEY_PORT);
        alice.listen();


        alice.establishSessionWith("bob");
        bob.establishSessionWith("alice");

        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            logger.error("Main thread interrupted while waiting for server to start", e);
            Thread.currentThread().interrupt();
        }

        String testMessageToBob = "Hi Bob!";
        alice.sendMessage("bob", testMessageToBob);

        String testMessageToAlice = "Hi Alice!";
        bob.sendMessage("alice", testMessageToAlice);

        // Keep main thread alive indefinitely
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
}
