package com.securechat.store;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.state.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class SignalStore implements SignalProtocolStore {

    private static final Logger logger = LoggerFactory.getLogger(SignalStore.class);

    private IdentityKeyPair identityKeyPair;
    private int registrationId;

    private final Map<Integer, PreKeyRecord> preKeyStore = new ConcurrentHashMap<>();
    private final Map<Integer, SignedPreKeyRecord> signedPreKeyStore = new ConcurrentHashMap<>();
    private final Map<SignalProtocolAddress, SessionRecord> sessionStore = new ConcurrentHashMap<>();
    private final Map<SignalProtocolAddress, IdentityKey> identityStore = new ConcurrentHashMap<>();

    public SignalStore() {
        // Keys to be initialized by initializeKeys()
    }

    public void initializeKeys(IdentityKeyPair identityKeyPair, int registrationId) {
        this.identityKeyPair = identityKeyPair;
        this.registrationId = registrationId;
        logger.info("Initialized IdentityKeyPair and registration ID {}", registrationId);
    }

    public void storePreKeyRecord(PreKeyRecord record) {
        preKeyStore.put(record.getId(), record);
        logger.info("Stored PreKey with ID: {}", record.getId());
    }

    public void storeSignedPreKeyRecord(SignedPreKeyRecord record) {
        signedPreKeyStore.put(record.getId(), record);
        logger.info("Stored SignedPreKey with ID: {}", record.getId());
    }

    // === IdentityKeyStore ===

    @Override
    public IdentityKeyPair getIdentityKeyPair() {
        if (identityKeyPair == null) {
            throw new IllegalStateException("IdentityKeyPair not initialized");
        }
        logger.debug("Retrieving IdentityKeyPair");
        return identityKeyPair;
    }

    @Override
    public int getLocalRegistrationId() {
        return registrationId;
    }

    @Override
    public boolean saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
        IdentityKey existing = identityStore.get(address);
        if (existing == null || !existing.equals(identityKey)) {
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
        PreKeyRecord record = preKeyStore.get(preKeyId);
        if (record == null) {
            throw new InvalidKeyIdException("No such pre-key: " + preKeyId);
        }
        return record;
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
        SignedPreKeyRecord record = signedPreKeyStore.get(signedPreKeyId);
        if (record == null) {
            throw new InvalidKeyIdException("No such signed pre-key: " + signedPreKeyId);
        }
        return record;
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
        logger.debug("Stored session for {} device {}", address.getName(), address.getDeviceId());
    }

    @Override
    public boolean containsSession(SignalProtocolAddress address) {
        return sessionStore.containsKey(address);
    }

    @Override
    public void deleteSession(SignalProtocolAddress address) {
        sessionStore.remove(address);
        logger.debug("Deleted session for {} device {}", address.getName(), address.getDeviceId());
    }

    @Override
    public void deleteAllSessions(String name) {
        sessionStore.keySet().removeIf(addr -> addr.getName().equals(name));
        logger.debug("Deleted all sessions for user {}", name);
    }

    // === Trusted Identity ===

    @Override
    public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction) {
        IdentityKey trusted = identityStore.get(address);
        return trusted == null || trusted.equals(identityKey);
    }
}
