package com.securechat.crypto.libsignal;

public record EncryptedMessageResult(byte[] ciphertext, boolean isPreKeyMessage) {}
