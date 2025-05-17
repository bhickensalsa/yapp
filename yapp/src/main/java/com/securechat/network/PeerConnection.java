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

    public void sendMessageObject(Object obj) throws IOException {
        synchronized (messageOutput) {
            messageOutput.writeObject(obj);
            messageOutput.flush();
        }
    }

    public Object receiveMessageObject() throws IOException, ClassNotFoundException {
        synchronized (messageInput) {
            return messageInput.readObject();
        }
    }

    public void sendPreKeyObject(Object obj) throws IOException {
        synchronized (preKeyOutput) {
            preKeyOutput.writeObject(obj);
            preKeyOutput.flush();
        }
    }

    public Object receivePreKeyObject() throws IOException, ClassNotFoundException {
        synchronized (preKeyInput) {
            return preKeyInput.readObject();
        }
    }

    public void close() throws IOException {
        IOException ex = null;
        try {
            if (messageOutput != null) messageOutput.close();
        } catch (IOException e) {
            ex = e;
        }
        try {
            if (messageInput != null) messageInput.close();
        } catch (IOException e) {
            if (ex == null) ex = e;
        }
        try {
            if (messageSocket != null && !messageSocket.isClosed()) messageSocket.close();
        } catch (IOException e) {
            if (ex == null) ex = e;
        }
        try {
            if (preKeyOutput != null) preKeyOutput.close();
        } catch (IOException e) {
            if (ex == null) ex = e;
        }
        try {
            if (preKeyInput != null) preKeyInput.close();
        } catch (IOException e) {
            if (ex == null) ex = e;
        }
        try {
            if (preKeySocket != null && !preKeySocket.isClosed()) preKeySocket.close();
        } catch (IOException e) {
            if (ex == null) ex = e;
        }
        if (ex != null) throw ex;
    }

    public String getRemoteAddress() {
        return messageSocket.getRemoteSocketAddress().toString();
    }
}
