package com.securechat.model;

public class KeyBundle {
    private byte[] identityKey;
    private byte[] signedPreKey;
    private byte[] oneTimePreKey;
    private byte[] signature;

    public KeyBundle(byte[] identityKey, byte[] signedPreKey, byte[] oneTimePreKey, byte[] signature) {
        this.identityKey = identityKey;
        this.signedPreKey = signedPreKey;
        this.oneTimePreKey = oneTimePreKey;
        this.signature = signature;
    }

    // Getters
    public byte[] getIdentityKey() { return identityKey; }
    public byte[] getSignedPreKey() { return signedPreKey; }
    public byte[] getOneTimePreKey() { return oneTimePreKey; }
    public byte[] getSignature() { return signature; }
}
