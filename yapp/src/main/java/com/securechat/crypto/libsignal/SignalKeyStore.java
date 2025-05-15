package com.securechat.crypto.libsignal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.state.*;
import org.whispersystems.libsignal.util.KeyHelper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SignalKeyStore implements SignalProtocolStore {

    private static final Logger logger = LoggerFactory.getLogger(SignalKeyStore.class);

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
        logger.info("Generated new IdentityKeyPair and registrationId {}", registrationId);
    }

    // === IdentityKeyStore ===
    @Override
    public IdentityKeyPair getIdentityKeyPair() {
        logger.debug("Retrieving IdentityKeyPair");
        return identityKeyPair;
    }

    @Override
    public int getLocalRegistrationId() {
        logger.debug("Retrieving local registration ID: {}", registrationId);
        return registrationId;
    }

    @Override
    public boolean saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
        logger.debug("Saving identity for address: {}", address);
        IdentityKey existing = identityStore.get(address);
        if (existing != null && !existing.equals(identityKey)) {
            identityStore.put(address, identityKey);
            logger.info("Identity updated for address: {}", address);
            return true;
        } else if (existing == null) {
            identityStore.put(address, identityKey);
            logger.info("New identity saved for address: {}", address);
            return true;
        }
        logger.debug("Identity for address {} is unchanged", address);
        return false;
    }

    @Override
    public IdentityKey getIdentity(SignalProtocolAddress address) {
        logger.debug("Getting identity for address: {}", address);
        return identityStore.get(address);
    }

    // === PreKeyStore ===
    @Override
    public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
        logger.debug("Loading PreKey with ID: {}", preKeyId);
        if (!preKeyStore.containsKey(preKeyId)) {
            logger.error("PreKey with ID {} not found", preKeyId);
            throw new InvalidKeyIdException("No such pre-key: " + preKeyId);
        }
        return preKeyStore.get(preKeyId);
    }

    @Override
    public void storePreKey(int preKeyId, PreKeyRecord record) {
        preKeyStore.put(preKeyId, record);
        logger.info("Stored PreKey with ID: {}", preKeyId);
    }

    @Override
    public boolean containsPreKey(int preKeyId) {
        boolean contains = preKeyStore.containsKey(preKeyId);
        logger.debug("Contains PreKey ID {}: {}", preKeyId, contains);
        return contains;
    }

    @Override
    public void removePreKey(int preKeyId) {
        preKeyStore.remove(preKeyId);
        logger.info("Removed PreKey with ID: {}", preKeyId);
    }

    // === SignedPreKeyStore ===
    @Override
    public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
        logger.debug("Loading SignedPreKey with ID: {}", signedPreKeyId);
        if (!signedPreKeyStore.containsKey(signedPreKeyId)) {
            logger.error("SignedPreKey with ID {} not found", signedPreKeyId);
            throw new InvalidKeyIdException("No such signed pre-key: " + signedPreKeyId);
        }
        return signedPreKeyStore.get(signedPreKeyId);
    }

    @Override
    public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
        signedPreKeyStore.put(signedPreKeyId, record);
        logger.info("Stored SignedPreKey with ID: {}", signedPreKeyId);
    }

    @Override
    public boolean containsSignedPreKey(int signedPreKeyId) {
        boolean contains = signedPreKeyStore.containsKey(signedPreKeyId);
        logger.debug("Contains SignedPreKey ID {}: {}", signedPreKeyId, contains);
        return contains;
    }

    @Override
    public void removeSignedPreKey(int signedPreKeyId) {
        signedPreKeyStore.remove(signedPreKeyId);
        logger.info("Removed SignedPreKey with ID: {}", signedPreKeyId);
    }

    @Override
    public List<SignedPreKeyRecord> loadSignedPreKeys() {
        logger.debug("Loading all SignedPreKeys");
        return new ArrayList<>(signedPreKeyStore.values());
    }

    // === SessionStore ===
    @Override
    public SessionRecord loadSession(SignalProtocolAddress address) {
        logger.debug("Loading session for address: {}", address);
        return sessionStore.getOrDefault(address, new SessionRecord());
    }

    @Override
    public List<Integer> getSubDeviceSessions(String name) {
        logger.debug("Getting sub-device sessions for user: {}", name);
        List<Integer> deviceIds = new ArrayList<>();
        for (SignalProtocolAddress addr : sessionStore.keySet()) {
            if (addr.getName().equals(name)) {
                deviceIds.add(addr.getDeviceId());
            }
        }
        logger.debug("Found {} sub-device sessions for user {}", deviceIds.size(), name);
        return deviceIds;
    }

    @Override
    public void storeSession(SignalProtocolAddress address, SessionRecord record) {
        sessionStore.put(address, record);
        logger.info("Stored session for address: {}", address);
    }

    @Override
    public boolean containsSession(SignalProtocolAddress address) {
        boolean contains = sessionStore.containsKey(address);
        logger.debug("Contains session for address {}: {}", address, contains);
        return contains;
    }

    @Override
    public void deleteSession(SignalProtocolAddress address) {
        sessionStore.remove(address);
        logger.info("Deleted session for address: {}", address);
    }

    @Override
    public void deleteAllSessions(String name) {
        logger.info("Deleting all sessions for user: {}", name);
        sessionStore.keySet().removeIf(addr -> addr.getName().equals(name));
    }

    @Override
    public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction) {
        IdentityKey trusted = identityStore.get(address);
        if (trusted == null) {
            logger.warn("No trusted identity for address {}, trusting first seen key", address);
            return true;
        }
        boolean trustedMatch = trusted.equals(identityKey);
        logger.debug("Is trusted identity for {}: {}", address, trustedMatch);
        return trustedMatch;
    }

}
