package com.securechat;

import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;

import com.securechat.client.UserClient;
import com.securechat.crypto.KeyManager;
import com.securechat.crypto.libsignal.SignalKeyStore;
import com.securechat.server.Server;

public class Launcher {

    public static void main(String[] args) {
        
        int preKeyId = 12345;
        int signedPreKeyId = 67890;

        // Create and initialize the SignalKeyStore with keys before starting server/client
        SignalKeyStore keyStore = new SignalKeyStore();
        initializeKeys(keyStore, preKeyId, signedPreKeyId);

        if (args.length > 0 && args[0].equals("server")) {
            // Start server with initialized keys
            new Server(8888, keyStore).start();
        } else {
            // Start server in a new thread
            Thread serverThread = new Thread(() -> {
                new Server(8888, keyStore).start();
            });
            serverThread.setDaemon(true); // So JVM can exit if main ends
            serverThread.start();

            try {
                // Wait briefly to ensure server starts before client connects
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

            // Create a client for user "alice" with the same key store
            UserClient client = new UserClient("alice", keyStore);

            // true = this client initiates the connection and sends first
            client.connectToPeer("localhost", 8888, true);

            client.listen();

            // Example send (plaintext will be encrypted internally)
            client.sendMessage("bob", "Hello Bob! This message is encrypted.");
        }
    }

    private static void initializeKeys(SignalKeyStore keyStore, int preKeyId, int signedPreKeyId) {
        KeyManager keyManager = new KeyManager();

        // Generate and store a PreKey
        PreKeyRecord preKey = keyManager.generatePreKey(preKeyId);
        keyStore.storePreKey(preKeyId, preKey);

        // Generate and store a SignedPreKey
        SignedPreKeyRecord signedPreKey = keyManager.generateSignedPreKey(keyStore.getIdentityKeyPair(), signedPreKeyId);
        keyStore.storeSignedPreKey(signedPreKeyId, signedPreKey);
    }
}
