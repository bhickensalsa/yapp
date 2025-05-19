package com.securechat;

import com.securechat.client.UserClient;
import com.securechat.server.Server;
import com.securechat.store.SignalStore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Launcher {

    private static final Logger logger = LoggerFactory.getLogger(Launcher.class);

    private static final String SERVER_ID = "localhost";
    private static final int MESSAGE_PORT = 8888;

    public static void main(String[] args) {

        final String aliceId = "alice";
        final int aliceDeviceId = 1;
        final int alicePreKeyId = 1001;
        final int aliceSignedPreKeyId = 1002;

        final String bobId = "bob";
        final int bobDeviceId = 2;
        final int bobPreKeyId = 2001;
        final int bobSignedPreKeyId = 2002;

        // Start the server
        Server server = new Server(MESSAGE_PORT);
        Thread serverThread = new Thread(server::start, "ServerThread");
        serverThread.start();
        logger.info("Server started on port {}", MESSAGE_PORT);

        waitMillis(2000); // Give server time to start

        // Create client stores (one per client)
        SignalStore aliceStore = new SignalStore();
        SignalStore bobStore = new SignalStore();

        // Create clients with their stores and key IDs
        UserClient alice = new UserClient(aliceId, aliceDeviceId, aliceStore, alicePreKeyId, aliceSignedPreKeyId);
        UserClient bob = new UserClient(bobId, bobDeviceId, bobStore, bobPreKeyId, bobSignedPreKeyId);

        // Initialize keys within clients
        alice.initializeUser();
        bob.initializeUser();

        // Connect clients to the server
        try {
            alice.connectToServer(SERVER_ID, MESSAGE_PORT);
            bob.connectToServer(SERVER_ID, MESSAGE_PORT);
        } catch (Exception e) {
            logger.error("Failed to connect clients to server", e);
            return;
        }

        waitMillis(2500); // Wait for bundles to register

        // Establish sessions (one side initiates)
        alice.establishSession(bobId, bobDeviceId);
        //bob.establishSession(aliceId, aliceDeviceId); // Optional, Bob can wait for Alice's prekey message

        waitMillis(2500); // Wait for sessions to finalize

        // Exchange messages, specifying peer device IDs explicitly
        alice.sendMessage(bobId, bobDeviceId, "Hi Bob!");
        bob.sendMessage(aliceId, aliceDeviceId, "Hi Alice!");

        waitMillis(1000);

        alice.sendMessage(bobId, bobDeviceId, "Are you available for a call?");
        bob.sendMessage(aliceId, aliceDeviceId, "Sure, let's do it!");

        // Keep main thread alive so clients can keep running
        try {
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            logger.error("Main thread interrupted", e);
            Thread.currentThread().interrupt();
        }
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
