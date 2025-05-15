package com.securechat.crypto;

public class EncryptionManager {

    private final Encryptor encryptor;

    public EncryptionManager(Encryptor encryptor) {
        this.encryptor = encryptor;
    }

    public String encryptMessage(String message, byte[] publicKey) throws Exception {
        return encryptor.encrypt(message, publicKey);
    }

    public String decryptMessage(String cipherText, byte[] privateKey) throws Exception {
        return encryptor.decrypt(cipherText, privateKey);
    }
}
