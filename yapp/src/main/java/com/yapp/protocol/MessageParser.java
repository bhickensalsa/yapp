package com.yapp.protocol;

import java.io.*;
import java.util.logging.Logger;

public class MessageParser {

    private static final Logger logger = Logger.getLogger(MessageParser.class.getName());

    /**
     * Sends a message over the given DataOutputStream.
     * @param out the DataOutputStream to send the message
     * @param msg the message to send
     * @throws IOException if there is an I/O error during the sending process
     */
    public static void send(DataOutputStream out, Message msg) throws IOException {
        if (msg == null || msg.getPayload() == null) {
            throw new IllegalArgumentException("Message or payload cannot be null");
        }

        // Log sending the message (for debugging purposes)
        logger.info("Sending message of type: " + msg.getType() + " with payload size: " + msg.getPayload().length);

        out.writeInt(msg.getType().ordinal());  // Send message type
        out.writeInt(msg.getPayload().length);  // Send payload length
        out.write(msg.getPayload());            // Send the actual payload
        out.flush();
    }

    /**
     * Receives a message from the given DataInputStream.
     * @param in the DataInputStream to receive the message from
     * @return the received Message object
     * @throws IOException if there is an I/O error during the receiving process
     */
    public static Message receive(DataInputStream in) throws IOException {
        try {
            // Read the type of the message (ordinal of the enum)
            int typeOrdinal = in.readInt();
            // Read the length of the payload
            int length = in.readInt();
            if (length < 0) {
                throw new IOException("Invalid message length: " + length);
            }
            
            byte[] data = new byte[length];
            in.readFully(data);  // Read the actual payload data

            // Log received message (for debugging purposes)
            logger.info("Received message of type: " + MessageType.values()[typeOrdinal] + " with payload size: " + length);

            // Validate type ordinal and create the message
            if (typeOrdinal < 0 || typeOrdinal >= MessageType.values().length) {
                throw new IOException("Invalid message type ordinal: " + typeOrdinal);
            }

            return new Message(MessageType.values()[typeOrdinal], data);
        } catch (IOException e) {
            logger.severe("Error receiving message: " + e.getMessage());
            throw e;  // Re-throw the IOException after logging it
        }
    }
}
