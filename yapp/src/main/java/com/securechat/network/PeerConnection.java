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
        output.flush();
        this.input = new ObjectInputStream(socket.getInputStream());
    }

    public void sendObject(Object obj) throws IOException {
        output.writeObject(obj);
        output.flush();
    }

    public Object receiveObject() throws IOException, ClassNotFoundException {
        return input.readObject();
    }

    public void close() throws IOException {
        socket.close();
    }

    public String getRemoteAddress() {
        return socket.getRemoteSocketAddress().toString();
    }

    public InputStream getInputStream() throws IOException {
        return socket.getInputStream();
    }

    public OutputStream getOutputStream() throws IOException {
        return socket.getOutputStream();
    }
}
