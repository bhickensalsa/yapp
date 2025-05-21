package com.securechat.ui;

import com.securechat.client.UserClient;
import com.securechat.store.SignalStore;
import com.securechat.protocol.PacketType;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JavaFX UI control for the SecureChat client application.
 *
 * <p>This UI allows the user to connect to a server, establish a secure session with a peer,
 * and send encrypted messages. It displays chat messages and status updates.
 *
 * <p>Uses SLF4J for logging internal events and errors, while also displaying
 * relevant messages in the chat area for user feedback.
 * 
 * <p>All UI updates are performed on the JavaFX Application Thread.
 * 
 * @author bhickensalsa
 * @version 0.2
 */
public class ClientControlUI extends VBox {
    private static final Logger logger = LoggerFactory.getLogger(ClientControlUI.class);

    private final TextField userIdField = new TextField();
    private final TextField userDeviceIdField = new TextField();
    private final TextField peerIdField = new TextField();
    private final TextField peerDeviceIdField = new TextField();

    private final Button connectButton = new Button("Connect to Server");
    private final Button establishSessionButton = new Button("Establish Session");
    private final Button sendButton = new Button("Send Message");

    private final TextArea chatArea = new TextArea();
    private final TextField messageField = new TextField();

    private UserClient client;
    private SignalStore store;

    /**
     * Constructs the ClientControlUI and initializes the layout and event handlers.
     */
    public ClientControlUI() {
        setupLayout();
        setupActions();
    }

    /**
     * Configures the UI layout components and their properties.
     */
    private void setupLayout() {
        setSpacing(10);
        setPadding(new Insets(10));

        chatArea.setEditable(false);
        chatArea.setPrefHeight(300);

        userIdField.setPromptText("Your User ID (e.g. alice)");
        userDeviceIdField.setPromptText("Your Device ID (e.g. 1)");
        peerIdField.setPromptText("Peer User ID (e.g. bob)");
        peerDeviceIdField.setPromptText("Peer Device ID (e.g. 2)");
        messageField.setPromptText("Type message here");

        HBox idsBox = new HBox(10,
            new VBox(new Label("Your User ID:"), userIdField),
            new VBox(new Label("Your Device ID:"), userDeviceIdField),
            new VBox(new Label("Peer User ID:"), peerIdField),
            new VBox(new Label("Peer Device ID:"), peerDeviceIdField)
        );

        HBox sessionBox = new HBox(10, connectButton, establishSessionButton);
        HBox sendBox = new HBox(10, messageField, sendButton);

        getChildren().addAll(idsBox, sessionBox, chatArea, sendBox);

        establishSessionButton.setDisable(true);
        sendButton.setDisable(true);
    }

    /**
     * Attaches event handlers to buttons and input fields.
     */
    private void setupActions() {
        connectButton.setOnAction(e -> connectToServer());
        establishSessionButton.setOnAction(e -> establishSession());
        sendButton.setOnAction(e -> sendMessage());

        // Send message on Enter key press in message field
        messageField.setOnAction(e -> sendMessage());
    }

    /**
     * Attempts to connect to the chat server using the entered user credentials.
     * Displays status messages and enables session establishment on success.
     */
    private void connectToServer() {
        String userId = userIdField.getText().trim();
        String userDeviceIdStr = userDeviceIdField.getText().trim();

        if (userId.isEmpty() || userDeviceIdStr.isEmpty()) {
            appendLog("Please enter your User ID and Device ID");
            return;
        }

        int userDeviceId;
        try {
            userDeviceId = Integer.parseInt(userDeviceIdStr);
        } catch (NumberFormatException ex) {
            appendLog("Device ID must be a number");
            return;
        }

        store = new SignalStore();
        client = new UserClient(userId, userDeviceId, store, 1001, 1002);

        try {
            client.initializeUser();
            client.connectToServer("localhost", 8888);

            appendLog("Connected to server as " + userId);
            logger.info("User '{}' connected to server at localhost:8888", userId);

            establishSessionButton.setDisable(false);

            client.setIncomingMessageListener((sender, message) -> 
                Platform.runLater(() -> {
                    appendLog(sender + ": " + message);
                    logger.info("Received message from {}: {}", sender, message);
                })
            );

        } catch (Exception ex) {
            appendLog("Failed to connect: " + ex.getMessage());
            logger.error("Connection failed for user {}: {}", userId, ex.getMessage(), ex);
        }
    }

    /**
     * Establishes a secure session with the specified peer.
     * Simulates sending a prekey message to initiate the session.
     */
    private void establishSession() {
        if (client == null) {
            appendLog("Connect to server first!");
            return;
        }

        String peerId = peerIdField.getText().trim();
        String peerDeviceIdStr = peerDeviceIdField.getText().trim();

        if (peerId.isEmpty() || peerDeviceIdStr.isEmpty()) {
            appendLog("Please enter peer User ID and Device ID");
            return;
        }

        int peerDeviceId;
        try {
            peerDeviceId = Integer.parseInt(peerDeviceIdStr);
        } catch (NumberFormatException ex) {
            appendLog("Peer Device ID must be a number");
            return;
        }

        try {
            String fakePreKeyMessage = "Hello " + peerId + "! This is prekey message.";
            client.establishSession(peerId, peerDeviceId, fakePreKeyMessage);

            appendLog("Session established with " + peerId);
            logger.info("Session established between user '{}' and peer '{}'", userIdField, peerId);

            sendButton.setDisable(false);
        } catch (Exception ex) {
            appendLog("Failed to establish session: " + ex.getMessage());
            logger.error("Failed to establish session with peer {}: {}", peerId, ex.getMessage(), ex);
        }
    }

    /**
     * Sends a message to the connected peer via the client.
     */
    private void sendMessage() {
        if (client == null) {
            appendLog("Connect and establish session first!");
            return;
        }

        String peerId = peerIdField.getText().trim();
        int peerDeviceId;
        try {
            peerDeviceId = Integer.parseInt(peerDeviceIdField.getText().trim());
        } catch (NumberFormatException e) {
            appendLog("Peer Device ID invalid");
            return;
        }

        String message = messageField.getText().trim();
        if (message.isEmpty()) {
            return;
        }

        try {
            client.sendMessage(peerId, peerDeviceId, message, PacketType.MESSAGE);
            appendLog("Me: " + message);
            logger.info("Sent message to {}: {}", peerId, message);
            messageField.clear();
        } catch (Exception e) {
            appendLog("Failed to send message: " + e.getMessage());
            logger.error("Failed to send message to peer {}: {}", peerId, e.getMessage(), e);
        }
    }

    /**
     * Appends text to the chat area UI on the JavaFX Application Thread.
     *
     * @param text the text message to append
     */
    private void appendLog(String text) {
        Platform.runLater(() -> chatArea.appendText(text + "\n"));
    }

    /**
     * Opens a JavaFX Stage containing this UI.
     *
     * <p>Note: This should be called from the JavaFX Application thread or from main with
     * JavaFX platform started.
     */
    public static void openStage() {
        Platform.startup(() -> {
            Stage stage = new Stage();
            ClientControlUI controlUI = new ClientControlUI();
            stage.setScene(new Scene(controlUI, 600, 400));
            stage.setTitle("SecureChat Client");
            stage.show();
        });
    }
}
