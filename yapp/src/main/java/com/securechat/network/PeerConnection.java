package com.securechat.network;

import java.io.*;
import java.net.Socket;

public class PeerConnection {

    private final Socket messageSocket;
    private final ObjectInputStream messageInput;
    private final ObjectOutputStream messageOutput;

    private final Socket preKeySocket;
    private final ObjectInputStream preKeyInput;
    private final ObjectOutputStream preKeyOutput;

    // Constructor takes two sockets: one for messages, one for prekeys
    public PeerConnection(Socket messageSocket, Socket preKeySocket) throws IOException {
        this.messageSocket = messageSocket;
        this.messageOutput = new ObjectOutputStream(messageSocket.getOutputStream());
        this.messageOutput.flush();
        this.messageInput = new ObjectInputStream(messageSocket.getInputStream());

        this.preKeySocket = preKeySocket;
        this.preKeyOutput = new ObjectOutputStream(preKeySocket.getOutputStream());
        this.preKeyOutput.flush();
        this.preKeyInput = new ObjectInputStream(preKeySocket.getInputStream());
    }

    // Send a message object on the message stream
    public void sendMessageObject(Object obj) throws IOException {
        messageOutput.writeObject(obj);
        messageOutput.flush();
    }

    // Receive a message object on the message stream
    public Object receiveMessageObject() throws IOException, ClassNotFoundException {
        return messageInput.readObject();
    }

    // Send a prekey-related object on the prekey stream
    public void sendPreKeyObject(Object obj) throws IOException {
        preKeyOutput.writeObject(obj);
        preKeyOutput.flush();
    }

    // Receive a prekey-related object on the prekey stream
    public Object receivePreKeyObject() throws IOException, ClassNotFoundException {
        return preKeyInput.readObject();
    }

    public void close() throws IOException {
        try {
            messageSocket.close();
        } finally {
            preKeySocket.close();
        }
    }

    public String getRemoteAddress() {
        return messageSocket.getRemoteSocketAddress().toString();
    }
}
