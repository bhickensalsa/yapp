package com.securechat.crypto.libsignal;

import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.state.*;
import org.whispersystems.libsignal.protocol.*;

public class SignalProtocolManager {

    private final SignalProtocolStore store;

    public SignalProtocolManager(SignalProtocolStore store) {
        this.store = store;
    }

    // Initializes a session with a remote user by processing their prekey bundle.
    public void initializeSession(SignalProtocolAddress remoteAddress, PreKeyBundle preKeyBundle) {
        try {
            SessionBuilder sessionBuilder = new SessionBuilder(store, remoteAddress);
            sessionBuilder.process(preKeyBundle);
        } catch (InvalidKeyException | UntrustedIdentityException e) {
            System.err.println("Failed to initialize session: " + e.getMessage());
        }
    }

    // Encrypts a plaintext message for the given recipient.
    public byte[] encryptMessage(SignalProtocolAddress recipient, String plaintext) {
        try {
            SessionCipher cipher = new SessionCipher(store, recipient);
            byte[] ciphertext = cipher.encrypt(plaintext.getBytes()).serialize();
            return ciphertext;
        } catch (UntrustedIdentityException e) {
            System.err.println("Failed to encrypt message: " + e.getMessage());
            return null;
        }
    }

    // Decrypts an encrypted message from the sender.
    public String decryptMessage(SignalProtocolAddress sender, byte[] encryptedMessageBytes) {
        try {
            SessionCipher cipher = new SessionCipher(store, sender);
            SignalMessage encryptedMessage = new SignalMessage(encryptedMessageBytes);
            byte[] decryptedBytes = cipher.decrypt(encryptedMessage);
            return new String(decryptedBytes);
        } catch (InvalidMessageException | LegacyMessageException | DuplicateMessageException | 
        NoSessionException | UntrustedIdentityException e) {
            System.err.println("Failed to decrypt message: " + e.getMessage());
            return null;
        }
    }

    // Encrypts a plaintext message for an unestablished session using a PreKeySignalMessage.
    public byte[] encryptPreKeyMessage(SignalProtocolAddress recipient, String plaintext) {
        try {
            SessionCipher cipher = new SessionCipher(store, recipient);
            byte[] ciphertext = cipher.encrypt(plaintext.getBytes()).serialize();
            return ciphertext;
        } catch (UntrustedIdentityException e) {
            System.err.println("Failed to encrypt pre-key message: " + e.getMessage());
            return null;
        }
    }

    // Decrypts a PreKeySignalMessage from the sender and establishes a session.
    public String decryptPreKeyMessage(SignalProtocolAddress sender, byte[] preKeyMessageBytes) {
        try {
            PreKeySignalMessage preKeySignalMessage = new PreKeySignalMessage(preKeyMessageBytes);
            SessionCipher cipher = new SessionCipher(store, sender);
            byte[] decryptedBytes = cipher.decrypt(preKeySignalMessage);
            return new String(decryptedBytes);
        } catch (UntrustedIdentityException | InvalidMessageException | InvalidVersionException | DuplicateMessageException | LegacyMessageException | InvalidKeyIdException | InvalidKeyException e) {
            System.err.println("Failed to decrypt pre-key message: " + e.getMessage());
            return null;
        }
    }
}
