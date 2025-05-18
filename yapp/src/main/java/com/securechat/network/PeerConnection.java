package com.securechat.network;

import java.io.*;
import java.net.Socket;

public class PeerConnection {

    private final Socket socket;
    private final ObjectInputStream input;
    private final ObjectOutputStream output;

    public PeerConnection(Socket socket) throws IOException {
        this.socket = socket;
        this.output = new ObjectOutputStream(socket.getOutputStream());
        this.output.flush();
        this.input = new ObjectInputStream(socket.getInputStream());
    }

    public void sendUserId(String userId) throws IOException {
        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
        dos.writeUTF(userId);
        dos.flush();
    }

    public void sendMessageObject(Object obj) throws IOException {
        synchronized (output) {
            output.writeObject(obj);
            output.flush();
        }
    }

    public Object receiveMessageObject() throws IOException, ClassNotFoundException {
        synchronized (input) {
            return input.readObject();
        }
    }

    public void close() throws IOException {
        IOException ex = null;
        try {
            if (output != null) output.close();
        } catch (IOException e) {
            ex = e;
        }
        try {
            if (input != null) input.close();
        } catch (IOException e) {
            if (ex == null) ex = e;
        }
        try {
            if (socket != null && !socket.isClosed()) socket.close();
        } catch (IOException e) {
            if (ex == null) ex = e;
        }
        if (ex != null) throw ex;
    }

    public String getRemoteAddress() {
        return socket.getRemoteSocketAddress().toString();
    }
}
