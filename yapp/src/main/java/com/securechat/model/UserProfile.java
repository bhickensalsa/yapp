package com.securechat.model;

public class UserProfile {
    private String username;
    private String userId;
    private byte[] publicIdentityKey;

    // Constructors
    public UserProfile(String username, String userId, byte[] publicIdentityKey) {
        this.username = username;
        this.userId = userId;
        this.publicIdentityKey = publicIdentityKey;
    }

    // Getters and setters
    public String getUsername() { return username; }
    public String getUserId() { return userId; }
    public byte[] getPublicIdentityKey() { return publicIdentityKey; }
}
