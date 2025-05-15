package com.securechat;

import com.securechat.client.UserClient;
import com.securechat.crypto.KeyManager;
import com.securechat.crypto.libsignal.SignalKeyStore;
import com.securechat.server.Server;
import com.securechat.store.InMemoryPreKeyStore;
import com.securechat.store.PreKeyStore;

public class Launcher {

    public static void main(String[] args) {

        int serverPreKeyId = 1;
        int serverSignedPreKeyId = 1;

        int alicePreKeyId = 1001;
        int aliceSignedPreKeyId = 1002;

        int bobPreKeyId = 2001;
        int bobSignedPreKeyId = 2002;
        
        // initializeKeys fills keys with those IDs
        PreKeyStore preKeyStore = new InMemoryPreKeyStore();
        SignalKeyStore serverKeyStore = new SignalKeyStore();
        initializeKeys(serverKeyStore, serverPreKeyId, serverSignedPreKeyId);

        SignalKeyStore aliceKeyStore = new SignalKeyStore();
        initializeKeys(aliceKeyStore, alicePreKeyId, aliceSignedPreKeyId);
        
        SignalKeyStore bobKeyStore = new SignalKeyStore();
        initializeKeys(bobKeyStore, bobPreKeyId, bobSignedPreKeyId);
        

        Server server = new Server(8888, serverKeyStore, preKeyStore, serverPreKeyId, serverSignedPreKeyId);
        new Thread(server::start).start();
        // Do NOT set daemon here, so server keeps running
        // serverThread.setDaemon(true);

        try {
            Thread.sleep(2000); // wait for server to start
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        UserClient alice = new UserClient("alice", aliceKeyStore, alicePreKeyId, aliceSignedPreKeyId);
        alice.connectToServer("localhost", 8888);


        UserClient bob = new UserClient("bob", bobKeyStore, bobPreKeyId, bobSignedPreKeyId);
        bob.connectToServer("localhost", 8888);

        // Assuming establishSessionWith is implemented and returns boolean
        if (alice.establishSessionWith("bob")) {
            alice.listen();
            alice.sendMessage("bob", "Hello Bob! This message is encrypted.");
        }

        bob.listen();

        // Keep main thread alive to keep app running:
        try {
            Thread.currentThread().join(); // Wait indefinitely
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    private static void initializeKeys(SignalKeyStore keyStore, int preKeyId, int signedPreKeyId) {
        KeyManager keyManager = new KeyManager();

        // Generate and store a PreKey
        var preKey = keyManager.generatePreKey(preKeyId);
        keyStore.storePreKey(preKeyId, preKey);

        // Generate and store a SignedPreKey
        var signedPreKey = keyManager.generateSignedPreKey(keyStore.getIdentityKeyPair(), signedPreKeyId);
        keyStore.storeSignedPreKey(signedPreKeyId, signedPreKey);
    }
}
