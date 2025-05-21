package com.securechat;

import com.securechat.ui.ClientControlUI;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.stage.Stage;

/**
 * The main JavaFX application launcher class for the SecureChat client UI.
 * <p>
 * This class extends {@link javafx.application.Application} and sets up
 * the primary stage, initializing the user interface by embedding
 * the {@link ClientControlUI} component.
 * </p>
 */
public class Launcher extends Application {

    /**
     * The entry point of the Java application.
     * Delegates to the JavaFX runtime.
     *
     * @param args command-line arguments (ignored)
     */
    public static void main(String[] args) {
        launch(args);
    }

    /**
     * Called by the JavaFX runtime to start the application.
     * Sets up the primary stage with the client UI scene.
     *
     * @param primaryStage the main stage for this application
     */
    @Override
    public void start(Stage primaryStage) {
        ClientControlUI clientUI = new ClientControlUI();
        Scene scene = new Scene(clientUI, 600, 400);
        primaryStage.setScene(scene);
        primaryStage.setTitle("SecureChat Client");
        primaryStage.show();
    }
}
