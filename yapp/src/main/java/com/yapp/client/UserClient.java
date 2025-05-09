package com.yapp.client;

import com.yapp.encryption.Encryptor;
import com.yapp.encryption.KeyManager;
import com.yapp.protocol.Message;
import com.yapp.protocol.MessageParser;
import com.yapp.protocol.MessageType;
import com.yapp.utils.ConsoleLogger;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

/**
 * Handles connection, key exchange, and communication stream setup with the server.
 * Uses {@link MessageParser} to send and receive messages and an {@link Encryptor}
 * for message-level encryption.
 *
 * This class is designed to work with GUI or controller layers that manage
 * message handling beyond transport and cryptography setup.
 * 
 * @author Philip
 * @version 2025-05-09
 */
public class UserClient {
    private final Socket socket;
    private final DataInputStream in;
    private final DataOutputStream out;
    private final Encryptor encryptor;
    private PublicKey serverPublicKey;
    private final ConsoleLogger logger;
    private volatile boolean running;

    public UserClient(String host, int port, Encryptor encryptor, ConsoleLogger logger) throws IOException {
        this.encryptor = encryptor;
        this.logger = logger;
        this.socket = new Socket(host, port);
        this.in = new DataInputStream(socket.getInputStream());
        this.out = new DataOutputStream(socket.getOutputStream());
        this.running = true;
    }

    public void start() {
        try {
            logger.log("Connected to server.");

            // Send client's public key
            Message keyMsg = new Message(
                MessageType.KEY_EXCHANGE,
                encryptor.getPublicKey().getEncoded()
            );
            MessageParser.send(out, keyMsg);

            // Receive server's public key
            Message serverKeyMsg = MessageParser.receive(in);
            if (serverKeyMsg.getType() != MessageType.KEY_EXCHANGE) {
                throw new IOException("Unexpected message type: expected KEY_EXCHANGE");
            }
            serverPublicKey = KeyManager.decodePublicKey(serverKeyMsg.getPayload());

            logger.log("Key exchange complete. Chat is now encrypted.");

        } catch (IOException | GeneralSecurityException e) {
            logger.log("Startup failed: " + e.getMessage());
            stop();
        }
    }

    public void stop() {
        running = false;
        try {
            in.close();
            out.close();
            socket.close();
            logger.log("Connection closed.");
        } catch (IOException e) {
            logger.log("Error during shutdown: " + e.getMessage());
        }
    }

    // Accessors
    public DataInputStream getInputStream() {
        return in;
    }

    public DataOutputStream getOutputStream() {
        return out;
    }

    public PublicKey getServerPublicKey() {
        return serverPublicKey;
    }

    public Encryptor getEncryptor() {
        return encryptor;
    }

    public boolean isRunning() {
        return running;
    }
}
