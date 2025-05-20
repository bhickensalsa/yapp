package com.securechat.network;

import java.io.*;
import java.net.Socket;

/**
 * Represents a network connection to a peer using a socket with
 * object input/output streams for sending and receiving serializable objects.
 *
 * <p>This class wraps a {@link Socket} and provides thread-safe methods
 * to send and receive objects over the network connection.
 *
 * <p>It manages the underlying streams and socket lifecycle, including
 * proper closing of resources.
 * 
 * @author bhickensalsa
 * @version 0.1
 */
public class PeerConnection {

    private final Socket socket;
    private final ObjectInputStream input;
    private final ObjectOutputStream output;

    /**
     * Creates a PeerConnection wrapping the given socket.
     * Initializes the object input and output streams.
     *
     * @param socket the connected socket to the peer (non-null)
     * @throws IOException if an I/O error occurs during stream initialization
     */
    public PeerConnection(Socket socket) throws IOException {
        this.socket = socket;
        this.output = new ObjectOutputStream(socket.getOutputStream());
        this.output.flush();  // flush header to avoid stream deadlock
        this.input = new ObjectInputStream(socket.getInputStream());
    }

    /**
     * Sends a serializable object to the peer over the output stream.
     * This method is synchronized to prevent concurrent writes on the stream.
     *
     * @param obj the object to send (non-null, must be Serializable)
     * @throws IOException if an I/O error occurs during sending
     */
    public void sendMessageObject(Object obj) throws IOException {
        synchronized (output) {
            output.writeObject(obj);
            output.flush();
        }
    }

    /**
     * Receives a serializable object from the peer over the input stream.
     * This method is synchronized to prevent concurrent reads on the stream.
     *
     * @return the received object, castable by the caller
     * @throws IOException            if an I/O error occurs during reading
     * @throws ClassNotFoundException if the class of a serialized object cannot be found
     */
    public Object receiveMessageObject() throws IOException, ClassNotFoundException {
        synchronized (input) {
            return input.readObject();
        }
    }

    /**
     * Closes the peer connection by closing the input and output streams,
     * and the underlying socket.
     *
     * <p>If multiple close operations fail, only the first encountered exception
     * is thrown.
     *
     * @throws IOException if an I/O error occurs while closing any resource
     */
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

    /**
     * Returns the remote socket address of the connected peer as a string.
     *
     * @return the remote socket address string (never null)
     */
    public String getRemoteAddress() {
        return socket.getRemoteSocketAddress().toString();
    }
}
