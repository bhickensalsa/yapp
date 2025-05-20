package com.securechat.store;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.state.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An implementation of {@link SignalProtocolStore} that manages the storage
 * of cryptographic keys, sessions, and identities required for the Signal protocol.
 * <p>
 * This store holds identity keys, prekeys, signed prekeys, session records,
 * and identity keys for remote peers. It is thread-safe and uses concurrent
 * hash maps internally.
 * </p>
 * <p>
 * It also includes logging for all major operations to facilitate debugging
 * and tracking state changes.
 * </p>
 * 
 * @author bhickensalsa
 * @version 0.1
 */
public class SignalStore implements SignalProtocolStore {

    private static final Logger logger = LoggerFactory.getLogger(SignalStore.class);

    private static final String LOG_PREFIX = "[SignalStore]";

    private IdentityKeyPair identityKeyPair;
    private int registrationId;

    private final Map<Integer, PreKeyRecord> preKeyStore = new ConcurrentHashMap<>();
    private final Map<Integer, SignedPreKeyRecord> signedPreKeyStore = new ConcurrentHashMap<>();
    private final Map<SignalProtocolAddress, SessionRecord> sessionStore = new ConcurrentHashMap<>();
    private final Map<SignalProtocolAddress, IdentityKey> identityStore = new ConcurrentHashMap<>();

    /**
     * Constructs a new SignalStore instance.
     * Keys must be initialized separately via {@link #initializeKeys(IdentityKeyPair, int)}.
     */
    public SignalStore() {
        logger.debug("{} SignalStore instance created, awaiting keys initialization", LOG_PREFIX);
    }

    /**
     * Initializes the identity key pair and registration ID for this store.
     *
     * @param identityKeyPair the local IdentityKeyPair
     * @param registrationId the registration ID assigned to this client
     */
    public void initializeKeys(IdentityKeyPair identityKeyPair, int registrationId) {
        this.identityKeyPair = identityKeyPair;
        this.registrationId = registrationId;
        logger.info("{} Initialized IdentityKeyPair and registration ID {}", LOG_PREFIX, registrationId);
    }

    /**
     * Stores a {@link PreKeyRecord}.
     * 
     * @param record the PreKeyRecord to store; if null, operation is ignored
     */
    public void storePreKeyRecord(PreKeyRecord record) {
        if (record == null) {
            logger.warn("{} Attempted to store null PreKeyRecord", LOG_PREFIX);
            return;
        }
        preKeyStore.put(record.getId(), record);
        logger.info("{} Stored PreKey with ID: {}", LOG_PREFIX, record.getId());
    }

    /**
     * Stores a {@link SignedPreKeyRecord}.
     *
     * @param record the SignedPreKeyRecord to store; if null, operation is ignored
     */
    public void storeSignedPreKeyRecord(SignedPreKeyRecord record) {
        if (record == null) {
            logger.warn("{} Attempted to store null SignedPreKeyRecord", LOG_PREFIX);
            return;
        }
        signedPreKeyStore.put(record.getId(), record);
        logger.info("{} Stored SignedPreKey with ID: {}", LOG_PREFIX, record.getId());
    }

    // === IdentityKeyStore Methods ===

    /**
     * Retrieves the local identity key pair.
     *
     * @return the IdentityKeyPair
     * @throws IllegalStateException if the identity key pair has not been initialized
     */
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

    /**
     * Returns the local registration ID.
     *
     * @return the registration ID
     */
    @Override
    public int getLocalRegistrationId() {
        logger.debug("{} Retrieving local registration ID: {}", LOG_PREFIX, registrationId);
        return registrationId;
    }

    /**
     * Saves the identity key for a remote peer.
     *
     * @param address the SignalProtocolAddress of the remote peer
     * @param identityKey the IdentityKey to save
     * @return true if the identity was updated, false if unchanged or invalid input
     */
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

    /**
     * Retrieves the identity key for a remote peer.
     *
     * @param address the SignalProtocolAddress of the remote peer
     * @return the IdentityKey or null if not found or address is null
     */
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

    // === PreKeyStore Methods ===

    /**
     * Loads a PreKey record by its ID.
     *
     * @param preKeyId the ID of the PreKey
     * @return the PreKeyRecord
     * @throws InvalidKeyIdException if no record with the specified ID exists
     */
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

    /**
     * Stores a PreKey record by its ID.
     *
     * @param preKeyId the ID of the PreKey
     * @param record the PreKeyRecord to store; if null, operation is ignored
     */
    @Override
    public void storePreKey(int preKeyId, PreKeyRecord record) {
        if (record == null) {
            logger.warn("{} Attempted to store null PreKeyRecord for ID {}", LOG_PREFIX, preKeyId);
            return;
        }
        preKeyStore.put(preKeyId, record);
        logger.info("{} Stored PreKey with ID: {}", LOG_PREFIX, preKeyId);
    }

    /**
     * Checks if a PreKey with the specified ID exists.
     *
     * @param preKeyId the PreKey ID to check
     * @return true if the PreKey exists, false otherwise
     */
    @Override
    public boolean containsPreKey(int preKeyId) {
        boolean contains = preKeyStore.containsKey(preKeyId);
        logger.debug("{} Checking presence of PreKey {}: {}", LOG_PREFIX, preKeyId, contains);
        return contains;
    }

    /**
     * Removes the PreKey with the specified ID.
     *
     * @param preKeyId the ID of the PreKey to remove
     */
    @Override
    public void removePreKey(int preKeyId) {
        preKeyStore.remove(preKeyId);
        logger.info("{} Removed PreKey with ID: {}", LOG_PREFIX, preKeyId);
    }

    // === SignedPreKeyStore Methods ===

    /**
     * Loads a SignedPreKey record by its ID.
     *
     * @param signedPreKeyId the ID of the SignedPreKey
     * @return the SignedPreKeyRecord
     * @throws InvalidKeyIdException if no record with the specified ID exists
     */
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

    /**
     * Stores a SignedPreKey record by its ID.
     *
     * @param signedPreKeyId the ID of the SignedPreKey
     * @param record the SignedPreKeyRecord to store; if null, operation is ignored
     */
    @Override
    public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
        if (record == null) {
            logger.warn("{} Attempted to store null SignedPreKeyRecord for ID {}", LOG_PREFIX, signedPreKeyId);
            return;
        }
        signedPreKeyStore.put(signedPreKeyId, record);
        logger.info("{} Stored SignedPreKey with ID: {}", LOG_PREFIX, signedPreKeyId);
    }

    /**
     * Checks if a SignedPreKey with the specified ID exists.
     *
     * @param signedPreKeyId the SignedPreKey ID to check
     * @return true if the SignedPreKey exists, false otherwise
     */
    @Override
    public boolean containsSignedPreKey(int signedPreKeyId) {
        boolean contains = signedPreKeyStore.containsKey(signedPreKeyId);
        logger.debug("{} Checking presence of SignedPreKey {}: {}", LOG_PREFIX, signedPreKeyId, contains);
        return contains;
    }

    /**
     * Removes the SignedPreKey with the specified ID.
     *
     * @param signedPreKeyId the ID of the SignedPreKey to remove
     */
    @Override
    public void removeSignedPreKey(int signedPreKeyId) {
        signedPreKeyStore.remove(signedPreKeyId);
        logger.info("{} Removed SignedPreKey with ID: {}", LOG_PREFIX, signedPreKeyId);
    }

    /**
     * Loads all stored SignedPreKey records.
     *
     * @return a list of all SignedPreKeyRecords currently stored
     */
    @Override
    public List<SignedPreKeyRecord> loadSignedPreKeys() {
        logger.debug("{} Loading all SignedPreKeys, count: {}", LOG_PREFIX, signedPreKeyStore.size());
        return new ArrayList<>(signedPreKeyStore.values());
    }

    // === SessionStore Methods ===

    /**
     * Loads the session record for a given remote address.
     *
     * @param address the SignalProtocolAddress of the remote peer
     * @return the SessionRecord for the address, or a new empty SessionRecord if none exists or address is null
     */
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

    /**
     * Retrieves the list of device IDs for sub-device sessions associated with a given user name.
     *
     * @param name the user name whose sub-device sessions to retrieve
     * @return list of device IDs for the user's sub-device sessions
     */
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

    /**
     * Stores a session record for a given remote address.
     *
     * @param address the SignalProtocolAddress of the remote peer
     * @param record the SessionRecord to store
     */
    @Override
    public void storeSession(SignalProtocolAddress address, SessionRecord record) {
        if (address == null || record == null) {
            logger.warn("{} storeSession called with null address or record", LOG_PREFIX);
            return;
        }
        sessionStore.put(address, record);
        logger.debug("{} Stored session for {} device {}", LOG_PREFIX, address.getName(), address.getDeviceId());
    }

    /**
     * Checks whether a session exists for a given remote address.
     *
     * @param address the SignalProtocolAddress to check
     * @return true if a session exists, false otherwise
     */
    @Override
    public boolean containsSession(SignalProtocolAddress address) {
        boolean contains = sessionStore.containsKey(address);
        logger.debug("{} Checking if session exists for {} device {}: {}", LOG_PREFIX,
                address == null ? "null" : address.getName(),
                address == null ? "null" : address.getDeviceId(),
                contains);
        return contains;
    }

    /**
     * Deletes the session record for a given remote address.
     *
     * @param address the SignalProtocolAddress whose session to delete
     */
    @Override
    public void deleteSession(SignalProtocolAddress address) {
        if (address == null) {
            logger.warn("{} deleteSession called with null address", LOG_PREFIX);
            return;
        }
        sessionStore.remove(address);
        logger.debug("{} Deleted session for {} device {}", LOG_PREFIX, address.getName(), address.getDeviceId());
    }

    /**
     * Deletes all session records associated with a given user name.
     *
     * @param name the user name whose sessions should be deleted
     */
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

    // === Trusted Identity Methods ===

    /**
     * Determines whether the given identity key is trusted for a remote address.
     * <p>
     * If no previously stored identity exists for the address, the identity is
     * considered trusted by default.
     * </p>
     *
     * @param address the SignalProtocolAddress of the remote peer
     * @param identityKey the IdentityKey to verify
     * @param direction the direction of communication (sent/received)
     * @return true if the identity is trusted or not previously stored, false otherwise
     */
    @Override
    public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction) {
        if (address == null || identityKey == null) {
            logger.warn("{} isTrustedIdentity called with null address or identityKey", LOG_PREFIX);
            return false;
        }
        IdentityKey existing = identityStore.get(address);
        if (existing == null) {
            logger.info("{} No existing identity for {} device {}, trusting new identity", LOG_PREFIX, address.getName(), address.getDeviceId());
            return true;
        }
        boolean trusted = existing.equals(identityKey);
        logger.debug("{} Identity for {} device {} trusted? {}", LOG_PREFIX, address.getName(), address.getDeviceId(), trusted);
        return trusted;
    }
}
