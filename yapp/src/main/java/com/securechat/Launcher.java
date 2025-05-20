package com.securechat;

import com.securechat.client.UserClient;
import com.securechat.server.Server;
import com.securechat.store.SignalStore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The main application launcher for the SecureChat system.
 * <p>
 * This class initializes and starts the server and two user clients (Alice and Bob),
 * connects them, and simulates a secure chat conversation between the clients.
 * <p>
 * It also handles proper shutdown by registering a JVM shutdown hook that stops
 * the clients and server gracefully.
 * <p>
 * The launcher keeps the main thread alive indefinitely to maintain the running state.
 * </p>
 * 
 * @author bhickensalsa
 * @version 0.1
 */
public class Launcher {

    private static final Logger logger = LoggerFactory.getLogger(Launcher.class);

    /** The identifier for the server (localhost in this case). */
    private static final String SERVER_ID = "localhost";

    /** The port number on which the server listens for messages. */
    private static final int MESSAGE_PORT = 8888;

    /** Client instance representing Alice. */
    private static UserClient alice;

    /** Client instance representing Bob. */
    private static UserClient bob;

    /** Server instance handling message routing. */
    private static Server server;

    /**
     * The main entry point of the application.
     * <p>
     * This method sets up the server and clients, connects clients to the server,
     * simulates a secure chat conversation, registers a shutdown hook, and
     * keeps the main thread alive.
     * </p>
     *
     * @param args command-line arguments (not used)
     */
    public static void main(String[] args) {
        setupServer();

        waitMillis(2000); // Give server time to start

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

        // Register JVM shutdown hook to cleanly stop clients and server
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Shutdown initiated...");
            stopClients();
            stopServer();
        }));

        // Keep the main thread alive indefinitely to keep app running
        waitIndefinitely();
    }

    /**
     * Sets up and starts the server on the configured message port.
     * The server runs in a separate thread.
     */
    private static void setupServer() {
        server = new Server(MESSAGE_PORT);
        Thread serverThread = new Thread(server::start, "ServerThread");
        serverThread.start();
        logger.info("Server started on port {}", MESSAGE_PORT);
    }

    /**
     * Initializes the user clients Alice and Bob along with their Signal stores
     * and prepares them for connection.
     */
    private static void setupClients() {
        SignalStore aliceStore = new SignalStore();
        SignalStore bobStore = new SignalStore();

        alice = new UserClient("alice", 1, aliceStore, 1001, 1002);
        bob = new UserClient("bob", 2, bobStore, 2001, 2002);

        alice.initializeUser();
        bob.initializeUser();
    }

    /**
     * Connects both clients to the server at the specified server ID and port.
     *
     * @throws Exception if connecting either client to the server fails
     */
    private static void connectClients() throws Exception {
        alice.connectToServer(SERVER_ID, MESSAGE_PORT);
        bob.connectToServer(SERVER_ID, MESSAGE_PORT);
    }

    /**
     * Simulates a chat session between Bob and Alice by sending a series of
     * messages with delays to mimic real conversation timing.
     */
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

    /**
     * Stops the user clients Alice and Bob, if they are running.
     */
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

    /**
     * Stops the server, if it is running.
     */
    private static void stopServer() {
        if (server != null) {
            server.stop();
            logger.info("Server stopped.");
        }
    }

    /**
     * Causes the current thread to sleep for the specified number of milliseconds.
     * Logs and resets interrupt status if sleep is interrupted.
     *
     * @param millis the number of milliseconds to sleep
     */
    private static void waitMillis(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            logger.error("Sleep interrupted", e);
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Keeps the main thread alive indefinitely by waiting on the Launcher class's
     * monitor. This prevents the application from exiting while server and clients
     * run in other threads.
     */
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
