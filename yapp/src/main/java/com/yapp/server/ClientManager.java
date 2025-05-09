package com.yapp.server;

import com.yapp.encryption.Encryptor;
import com.yapp.protocol.Message;
import com.yapp.protocol.MessageParser;
import com.yapp.protocol.MessageType;
import com.yapp.utils.ConsoleLogger;

import java.io.*;
import java.net.Socket;
import java.security.PublicKey;

public class ClientManager implements Runnable {
    private final Socket socket;
    private final Encryptor encryptor;
    private final ConsoleLogger logger;
    private final Server server; // Reference to the server to broadcast messages
    private DataInputStream in;
    private DataOutputStream out;
    private PublicKey clientPublicKey;
    private volatile boolean running;

    public ClientManager(Socket socket, Encryptor encryptor, ConsoleLogger logger, Server server) {
        this.socket = socket;
        this.encryptor = encryptor;
        this.logger = logger;
        this.server = server;
        this.running = true;
    }

    @Override
    public void run() {
        try (
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream())
        ) {
            this.in = in;
            this.out = out;

            // Perform key exchange with the client
            keyExchange();

            // Start receiving and relaying messages
            while (running) {
                Message message = MessageParser.receive(in);
                if (message != null && message.getType() == MessageType.TEXT) {
                    server.broadcast(message, this); // Broadcast to other clients
                }
            }
        } catch (IOException e) {
            logger.log("Client connection error: " + e.getMessage());
        } finally {
            stop();
        }
    }

    /**
     * Perform the key exchange with the client.
     */
    private void keyExchange() throws IOException {
        // Key exchange logic
    }

    /**
     * Send a message to this client.
     */
    public void sendMessage(Message message) {
        try {
            MessageParser.send(out, message);
        } catch (IOException e) {
            logger.log("Failed to send message to client: " + e.getMessage());
        }
    }

    /**
     * Stop the client manager by closing the socket and cleaning up resources.
     */
    public void stop() {
        running = false;
        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        } catch (IOException e) {
            logger.log("Error closing client socket: " + e.getMessage());
        }
    }
}
