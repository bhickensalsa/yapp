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

    private static final String LOG_PREFIX = "[SignalStore]";

    private IdentityKeyPair identityKeyPair;
    private int registrationId;

    private final Map<Integer, PreKeyRecord> preKeyStore = new ConcurrentHashMap<>();
    private final Map<Integer, SignedPreKeyRecord> signedPreKeyStore = new ConcurrentHashMap<>();
    private final Map<SignalProtocolAddress, SessionRecord> sessionStore = new ConcurrentHashMap<>();
    private final Map<SignalProtocolAddress, IdentityKey> identityStore = new ConcurrentHashMap<>();

    public SignalStore() {
        // Keys to be initialized by initializeKeys()
        logger.debug("{} SignalStore instance created, awaiting keys initialization", LOG_PREFIX);
    }

    public void initializeKeys(IdentityKeyPair identityKeyPair, int registrationId) {
        this.identityKeyPair = identityKeyPair;
        this.registrationId = registrationId;
        logger.info("{} Initialized IdentityKeyPair and registration ID {}", LOG_PREFIX, registrationId);
    }

    public void storePreKeyRecord(PreKeyRecord record) {
        if (record == null) {
            logger.warn("{} Attempted to store null PreKeyRecord", LOG_PREFIX);
            return;
        }
        preKeyStore.put(record.getId(), record);
        logger.info("{} Stored PreKey with ID: {}", LOG_PREFIX, record.getId());
    }

    public void storeSignedPreKeyRecord(SignedPreKeyRecord record) {
        if (record == null) {
            logger.warn("{} Attempted to store null SignedPreKeyRecord", LOG_PREFIX);
            return;
        }
        signedPreKeyStore.put(record.getId(), record);
        logger.info("{} Stored SignedPreKey with ID: {}", LOG_PREFIX, record.getId());
    }

    // === IdentityKeyStore ===

    @Override
    public IdentityKeyPair getIdentityKeyPair() {
        if (identityKeyPair == null) {
            String errMsg = LOG_PREFIX + " IdentityKeyPair not initialized";
            logger.error(errMsg);
            throw new IllegalStateException(errMsg);
        }
        logger.debug("{} Retrieving IdentityKeyPair", LOG_PREFIX);
        return identityKeyPair;
    }

    @Override
    public int getLocalRegistrationId() {
        logger.debug("{} Retrieving local registration ID: {}", LOG_PREFIX, registrationId);
        return registrationId;
    }

    @Override
    public boolean saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
        if (address == null || identityKey == null) {
            logger.warn("{} saveIdentity called with null address or identityKey", LOG_PREFIX);
            return false;
        }
        IdentityKey existing = identityStore.get(address);
        if (existing == null || !existing.equals(identityKey)) {
            identityStore.put(address, identityKey);
            logger.info("{} Saved new identity for {} device {}", LOG_PREFIX, address.getName(), address.getDeviceId());
            return true;
        }
        logger.debug("{} Identity for {} device {} unchanged", LOG_PREFIX, address.getName(), address.getDeviceId());
        return false;
    }

    @Override
    public IdentityKey getIdentity(SignalProtocolAddress address) {
        if (address == null) {
            logger.warn("{} getIdentity called with null address", LOG_PREFIX);
            return null;
        }
        IdentityKey key = identityStore.get(address);
        logger.debug("{} Retrieved identity for {} device {}", LOG_PREFIX, address.getName(), address.getDeviceId());
        return key;
    }

    // === PreKeyStore ===

    @Override
    public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
        PreKeyRecord record = preKeyStore.get(preKeyId);
        if (record == null) {
            String errMsg = LOG_PREFIX + " No such pre-key: " + preKeyId;
            logger.error(errMsg);
            throw new InvalidKeyIdException(errMsg);
        }
        logger.debug("{} Loaded PreKey with ID: {}", LOG_PREFIX, preKeyId);
        return record;
    }

    @Override
    public void storePreKey(int preKeyId, PreKeyRecord record) {
        if (record == null) {
            logger.warn("{} Attempted to store null PreKeyRecord for ID {}", LOG_PREFIX, preKeyId);
            return;
        }
        preKeyStore.put(preKeyId, record);
        logger.info("{} Stored PreKey with ID: {}", LOG_PREFIX, preKeyId);
    }

    @Override
    public boolean containsPreKey(int preKeyId) {
        boolean contains = preKeyStore.containsKey(preKeyId);
        logger.debug("{} Checking presence of PreKey {}: {}", LOG_PREFIX, preKeyId, contains);
        return contains;
    }

    @Override
    public void removePreKey(int preKeyId) {
        preKeyStore.remove(preKeyId);
        logger.info("{} Removed PreKey with ID: {}", LOG_PREFIX, preKeyId);
    }

    // === SignedPreKeyStore ===

    @Override
    public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
        SignedPreKeyRecord record = signedPreKeyStore.get(signedPreKeyId);
        if (record == null) {
            String errMsg = LOG_PREFIX + " No such signed pre-key: " + signedPreKeyId;
            logger.error(errMsg);
            throw new InvalidKeyIdException(errMsg);
        }
        logger.debug("{} Loaded SignedPreKey with ID: {}", LOG_PREFIX, signedPreKeyId);
        return record;
    }

    @Override
    public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
        if (record == null) {
            logger.warn("{} Attempted to store null SignedPreKeyRecord for ID {}", LOG_PREFIX, signedPreKeyId);
            return;
        }
        signedPreKeyStore.put(signedPreKeyId, record);
        logger.info("{} Stored SignedPreKey with ID: {}", LOG_PREFIX, signedPreKeyId);
    }

    @Override
    public boolean containsSignedPreKey(int signedPreKeyId) {
        boolean contains = signedPreKeyStore.containsKey(signedPreKeyId);
        logger.debug("{} Checking presence of SignedPreKey {}: {}", LOG_PREFIX, signedPreKeyId, contains);
        return contains;
    }

    @Override
    public void removeSignedPreKey(int signedPreKeyId) {
        signedPreKeyStore.remove(signedPreKeyId);
        logger.info("{} Removed SignedPreKey with ID: {}", LOG_PREFIX, signedPreKeyId);
    }

    @Override
    public List<SignedPreKeyRecord> loadSignedPreKeys() {
        logger.debug("{} Loading all SignedPreKeys, count: {}", LOG_PREFIX, signedPreKeyStore.size());
        return new ArrayList<>(signedPreKeyStore.values());
    }

    // === SessionStore ===

    @Override
    public SessionRecord loadSession(SignalProtocolAddress address) {
        if (address == null) {
            logger.warn("{} loadSession called with null address", LOG_PREFIX);
            return new SessionRecord();
        }
        SessionRecord session = sessionStore.getOrDefault(address, new SessionRecord());
        logger.debug("{} Loaded session for {} device {}", LOG_PREFIX, address.getName(), address.getDeviceId());
        return session;
    }

    @Override
    public List<Integer> getSubDeviceSessions(String name) {
        List<Integer> deviceIds = new ArrayList<>();
        for (SignalProtocolAddress addr : sessionStore.keySet()) {
            if (addr.getName().equals(name)) {
                deviceIds.add(addr.getDeviceId());
            }
        }
        logger.debug("{} Found {} sub-device sessions for user {}", LOG_PREFIX, deviceIds.size(), name);
        return deviceIds;
    }

    @Override
    public void storeSession(SignalProtocolAddress address, SessionRecord record) {
        if (address == null || record == null) {
            logger.warn("{} storeSession called with null address or record", LOG_PREFIX);
            return;
        }
        sessionStore.put(address, record);
        logger.debug("{} Stored session for {} device {}", LOG_PREFIX, address.getName(), address.getDeviceId());
    }

    @Override
    public boolean containsSession(SignalProtocolAddress address) {
        boolean contains = sessionStore.containsKey(address);
        logger.debug("{} Checking if session exists for {} device {}: {}", LOG_PREFIX,
                address == null ? "null" : address.getName(),
                address == null ? "null" : address.getDeviceId(),
                contains);
        return contains;
    }

    @Override
    public void deleteSession(SignalProtocolAddress address) {
        if (address == null) {
            logger.warn("{} deleteSession called with null address", LOG_PREFIX);
            return;
        }
        sessionStore.remove(address);
        logger.debug("{} Deleted session for {} device {}", LOG_PREFIX, address.getName(), address.getDeviceId());
    }

    @Override
    public void deleteAllSessions(String name) {
        if (name == null) {
            logger.warn("{} deleteAllSessions called with null user name", LOG_PREFIX);
            return;
        }
        int before = sessionStore.size();
        sessionStore.keySet().removeIf(addr -> addr.getName().equals(name));
        int after = sessionStore.size();
        logger.debug("{} Deleted all sessions for user {} (removed {})", LOG_PREFIX, name, before - after);
    }

    // === Trusted Identity ===

    @Override
    public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction) {
        if (address == null || identityKey == null) {
            logger.warn("{} isTrustedIdentity called with null parameters", LOG_PREFIX);
            return false;
        }
        IdentityKey trusted = identityStore.get(address);
        boolean trustedResult = (trusted == null) || trusted.equals(identityKey);
        logger.debug("{} isTrustedIdentity for {} device {}: {}", LOG_PREFIX, address.getName(), address.getDeviceId(), trustedResult);
        return trustedResult;
    }
}
