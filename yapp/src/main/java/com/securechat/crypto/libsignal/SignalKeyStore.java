package com.securechat.crypto.libsignal;

import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.state.*;
import org.whispersystems.libsignal.util.KeyHelper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SignalKeyStore implements SignalProtocolStore {

    private final IdentityKeyPair identityKeyPair;
    private final int registrationId;

    private final Map<Integer, PreKeyRecord> preKeyStore = new HashMap<>();
    private final Map<Integer, SignedPreKeyRecord> signedPreKeyStore = new HashMap<>();
    private final Map<SignalProtocolAddress, SessionRecord> sessionStore = new HashMap<>();
    private final Map<SignalProtocolAddress, IdentityKey> identityStore = new HashMap<>();

    public SignalKeyStore() {
        // Generate identity key pair and registration ID
        this.identityKeyPair = KeyHelper.generateIdentityKeyPair();
        this.registrationId = KeyHelper.generateRegistrationId(false);
    }

    // === IdentityKeyStore ===
    @Override
    public IdentityKeyPair getIdentityKeyPair() {
        return identityKeyPair;
    }

    @Override
    public int getLocalRegistrationId() {
        return registrationId;
    }

    @Override
    public boolean saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
        IdentityKey existing = identityStore.get(address);
        if (existing != null && !existing.equals(identityKey)) {
            identityStore.put(address, identityKey);
            return true;
        } else if (existing == null) {
            identityStore.put(address, identityKey);
            return true;
        }
        return false;
    }

    @Override
    public IdentityKey getIdentity(SignalProtocolAddress address) {
        return identityStore.get(address);
    }

    // === PreKeyStore ===
    @Override
    public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
        if (!preKeyStore.containsKey(preKeyId)) {
            throw new InvalidKeyIdException("No such pre-key: " + preKeyId);
        }
        return preKeyStore.get(preKeyId);
    }

    @Override
    public void storePreKey(int preKeyId, PreKeyRecord record) {
        preKeyStore.put(preKeyId, record);
    }

    @Override
    public boolean containsPreKey(int preKeyId) {
        return preKeyStore.containsKey(preKeyId);
    }

    @Override
    public void removePreKey(int preKeyId) {
        preKeyStore.remove(preKeyId);
    }

    // === SignedPreKeyStore ===
    @Override
    public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
        if (!signedPreKeyStore.containsKey(signedPreKeyId)) {
            throw new InvalidKeyIdException("No such signed pre-key: " + signedPreKeyId);
        }
        return signedPreKeyStore.get(signedPreKeyId);
    }

    @Override
    public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
        signedPreKeyStore.put(signedPreKeyId, record);
    }

    @Override
    public boolean containsSignedPreKey(int signedPreKeyId) {
        return signedPreKeyStore.containsKey(signedPreKeyId);
    }

    @Override
    public void removeSignedPreKey(int signedPreKeyId) {
        signedPreKeyStore.remove(signedPreKeyId);
    }

    @Override
    public List<SignedPreKeyRecord> loadSignedPreKeys() {
        return new ArrayList<>(signedPreKeyStore.values());
    }

    // === SessionStore ===
    @Override
    public SessionRecord loadSession(SignalProtocolAddress address) {
        return sessionStore.getOrDefault(address, new SessionRecord());
    }

    @Override
    public List<Integer> getSubDeviceSessions(String name) {
        List<Integer> deviceIds = new ArrayList<>();
        for (SignalProtocolAddress addr : sessionStore.keySet()) {
            if (addr.getName().equals(name)) {
                deviceIds.add(addr.getDeviceId());
            }
        }
        return deviceIds;
    }

    @Override
    public void storeSession(SignalProtocolAddress address, SessionRecord record) {
        sessionStore.put(address, record);
    }

    @Override
    public boolean containsSession(SignalProtocolAddress address) {
        return sessionStore.containsKey(address);
    }

    @Override
    public void deleteSession(SignalProtocolAddress address) {
        sessionStore.remove(address);
    }

    @Override
    public void deleteAllSessions(String name) {
        sessionStore.keySet().removeIf(addr -> addr.getName().equals(name));
    }

    @Override
    public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction) {
        IdentityKey trusted = identityStore.get(address);
        // If we don't have a stored key, trust the first one we see
        if (trusted == null) {
            return true;
        }
        // Otherwise, check if the incoming key matches the stored key
        return trusted.equals(identityKey);
    }

}
