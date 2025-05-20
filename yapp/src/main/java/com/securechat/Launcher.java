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

    private static UserClient alice;
    private static UserClient bob;
    private static Server server;

    public static void main(String[] args) {
        setupServer();

        waitMillis(2000); // Let server start

        setupClients();

        try {
            connectClients();
            startChatSimulation();
        } catch (Exception e) {
            logger.error("Error during chat simulation", e);
            stopClients();
            stopServer();
            return;
        }

        // Register shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Shutdown initiated...");
            stopClients();
            stopServer();
        }));

        // Keep the main thread alive
        waitIndefinitely();
    }

    private static void setupServer() {
        server = new Server(MESSAGE_PORT);
        Thread serverThread = new Thread(server::start, "ServerThread");
        serverThread.start();
        logger.info("Server started on port {}", MESSAGE_PORT);
    }

    private static void setupClients() {
        SignalStore aliceStore = new SignalStore();
        SignalStore bobStore = new SignalStore();

        alice = new UserClient("alice", 1, aliceStore, 1001, 1002);
        bob = new UserClient("bob", 2, bobStore, 2001, 2002);

        alice.initializeUser();
        bob.initializeUser();
    }

    private static void connectClients() throws Exception {
        alice.connectToServer(SERVER_ID, MESSAGE_PORT);
        bob.connectToServer(SERVER_ID, MESSAGE_PORT);
    }

    private static void startChatSimulation() {
        bob.establishSession("alice", 1, "Hey Alice, here's my prekey message so you can start chatting securely!");
        waitMillis(3000); // Allow session to establish

        alice.sendMessage("bob", 2, "1 Hey Bob! Just got your prekey message. Looks like everything's working!");
        waitMillis(500);

        bob.sendMessage("alice", 1, "2 Awesome! I was a bit worried about the setup, but glad it's smooth now.");
        waitMillis(500);

        alice.sendMessage("bob", 2, "3 Yeah, it's been a pretty smooth experience. I like how quickly sessions establish.");
        waitMillis(500);

        bob.sendMessage("alice", 1, "4 For sure. We should probably do a more extended test though. Maybe simulate a real chat?");
        waitMillis(500);

        alice.sendMessage("bob", 2, "5 Agreed. So imagine we're planning for a weekend hike. What gear do you think we'll need?");
        waitMillis(500);

        bob.sendMessage("alice", 1, "6 Hmm, definitely hiking boots, a hydration pack, probably a jacket depending on the weather.");
        waitMillis(500);

        alice.sendMessage("bob", 2, "7 Good call. Also thinking of bringing a GPS tracker just in case. Signal might get weak in the mountains.");
        waitMillis(500);

        bob.sendMessage("alice", 1, "8 Smart. I'll also bring a small first aid kit. Better safe than sorry.");
        waitMillis(500);

        alice.sendMessage("bob", 2, "9 Nice. Okay, this conversation has now reached a healthy message count for load testing 😄");
        waitMillis(500);

        bob.sendMessage("alice", 1, "10 Haha, yeah! This should be a good stress test for both encryption and delivery reliability.");
        waitMillis(500);

        alice.sendMessage("bob", 2, "11 Absolutely. We'll check the logs after to verify everything went smoothly. Thanks for helping me test!");
        waitMillis(500);

        bob.sendMessage("alice", 1, "12 Anytime! Looking forward to seeing how well our secure chat holds up under more complex exchanges.");
    }

    private static void stopClients() {
        if (alice != null) {
            alice.stop();
            logger.info("Alice client stopped.");
        }
        if (bob != null) {
            bob.stop();
            logger.info("Bob client stopped.");
        }
    }

    private static void stopServer() {
        if (server != null) {
            server.stop();
            logger.info("Server stopped.");
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

    private static void waitIndefinitely() {
        try {
            synchronized (Launcher.class) {
                Launcher.class.wait();
            }
        } catch (InterruptedException e) {
            logger.warn("Main thread interrupted, exiting...");
            Thread.currentThread().interrupt();
        }
    }
}
