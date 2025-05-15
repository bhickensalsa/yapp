package com.securechat.network;

import java.io.*;
import java.net.Socket;

public class PeerConnection {

    private final Socket socket;
    private BufferedReader input;
    private BufferedWriter output;

    public PeerConnection(Socket socket) throws IOException {
        this.socket = socket;
        this.input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        this.output = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
    }

    public void send(String data) throws IOException {
        output.write(data);
        output.newLine();
        output.flush();
    }

    public String receive() throws IOException {
        return input.readLine();
    }

    public void close() throws IOException {
        socket.close();
    }

    public String getRemoteAddress() {
        return socket.getRemoteSocketAddress().toString();
    }

    // Add these two methods to get raw streams for ObjectInputStream/ObjectOutputStream
    public InputStream getInputStream() throws IOException {
        return socket.getInputStream();
    }

    public OutputStream getOutputStream() throws IOException {
        return socket.getOutputStream();
    }
}
