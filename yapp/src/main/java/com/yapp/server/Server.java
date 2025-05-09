package com.yapp.server;

import com.yapp.encryption.EncryptionManager;
import com.yapp.encryption.Encryptor;
import com.yapp.protocol.Message;
import com.yapp.utils.ConsoleLogger;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.util.concurrent.*;

public class Server {
    private final ServerSocket serverSocket;
    private final Encryptor encryptor;
    private final ConsoleLogger logger;
    private final ExecutorService clientThreadPool;
    private final CopyOnWriteArrayList<ClientManager> clients; // Thread-safe list of connected clients

    public Server(int port, Encryptor encryptor, ConsoleLogger logger) throws IOException {
        this.serverSocket = new ServerSocket(port);
        this.encryptor = encryptor;
        this.logger = logger;
        this.clientThreadPool = Executors.newCachedThreadPool();
        this.clients = new CopyOnWriteArrayList<>();
    }

    /**
     * Start the server and listen for client connections.
     */
    public void start() {
        logger.log("Server started. Waiting for connections...");

        try {
            while (!serverSocket.isClosed()) {
                Socket socket = serverSocket.accept();
                ClientManager clientManager = new ClientManager(socket, encryptor, logger, this);
                clientThreadPool.submit(clientManager);  // Submit client manager task to the thread pool
                clients.add(clientManager);
                logger.log("New client connected: " + socket.getInetAddress());
            }
        } catch (IOException e) {
            logger.log("Server error: " + e.getMessage());
        }
    }

    /**
     * Broadcast a message to all connected clients.
     */
    public void broadcast(Message message, ClientManager sender) {
        for (ClientManager client : clients) {
            if (client != sender) {  // Don't send the message back to the sender
                client.sendMessage(message);
            }
        }
    }

    /**
     * Stop the server and close all client connections.
     */
    public void stop() {
        try {
            for (ClientManager client : clients) {
                client.stop();
            }
            clientThreadPool.shutdown();
            if (!serverSocket.isClosed()) {
                serverSocket.close();
            }
            logger.log("Server stopped.");
        } catch (IOException e) {
            logger.log("Error stopping server: " + e.getMessage());
        }
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        ConsoleLogger logger = new ConsoleLogger();
        Encryptor encryptor = new EncryptionManager();
        Server server = new Server(8080, encryptor, logger);
        server.start();
    }
}
