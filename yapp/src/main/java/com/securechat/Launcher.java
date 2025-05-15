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
    private static int SERVER_SIGNED_PREKEY_ID = 1;
    private static int SERVER_PREKEY_ID = 1;

    public static void main(String[] args) {

        int alicePreKeyId = 1001;
        int aliceSignedPreKeyId = 1002;

        int bobPreKeyId = 2001;
        int bobSignedPreKeyId = 2002;

        logger.info("Initializing preKeyStore and keyStores");

        PreKeyStore preKeyStore = new InMemoryPreKeyStore();
        SignalKeyStore serverKeyStore = new SignalKeyStore();
        initializeKeys(serverKeyStore);

        SignalKeyStore aliceKeyStore = new SignalKeyStore();
        initializeKeys(aliceKeyStore, alicePreKeyId, aliceSignedPreKeyId);

        SignalKeyStore bobKeyStore = new SignalKeyStore();
        initializeKeys(bobKeyStore, bobPreKeyId, bobSignedPreKeyId);

        Server server = new Server(8888, serverKeyStore, preKeyStore);
        Thread serverThread = new Thread(server::start, "ServerThread");
        serverThread.start();
        logger.info("Server started on port 8888");

        try {
            Thread.sleep(2000); // wait for server to start
        } catch (InterruptedException e) {
            logger.error("Main thread interrupted while waiting for server to start", e);
            Thread.currentThread().interrupt();
        }

        UserClient alice = new UserClient("alice", aliceKeyStore, alicePreKeyId, aliceSignedPreKeyId);
        alice.connectToServer("localhost", 8888);

        UserClient bob = new UserClient("bob", bobKeyStore, bobPreKeyId, bobSignedPreKeyId);
        bob.connectToServer("localhost", 8888);
        bob.listen();

        if (alice.establishSessionWith("bob")) {
            alice.listen();
            alice.sendMessage("bob", "testmsg");
            logger.info("Alice sent an encrypted message to Bob");
        } else {
            logger.warn("Failed to establish secure session between Alice and Bob");
        }

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
