package com.securechat.crypto.libsignal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.*;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.IdentityKey;

import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A file-based implementation of SignalProtocolStore.
 * Stores sessions, identity keys, prekeys, and signed prekeys under a base directory.
 */
public class SimpleFileSessionStore implements SignalProtocolStore {

    private static final Logger logger = LoggerFactory.getLogger(SimpleFileSessionStore.class);

    private final File baseDir;
    private final File sessionsDir;
    private final File identityKeyFile;
    private final File preKeysDir;
    private final File signedPreKeysDir;

    private final IdentityKeyPair identityKeyPair;
    private final int registrationId;

    // In-memory caches to speed up access
    private final Map<SignalProtocolAddress, SessionRecord> sessions = new ConcurrentHashMap<>();
    private final Map<Integer, PreKeyRecord> preKeys = new ConcurrentHashMap<>();
    private final Map<Integer, SignedPreKeyRecord> signedPreKeys = new ConcurrentHashMap<>();
    private final Map<String, IdentityKey> trustedKeys = new ConcurrentHashMap<>();

    public SimpleFileSessionStore(File baseDir, IdentityKeyPair identityKeyPair, int registrationId) {
        this.baseDir = baseDir;
        this.identityKeyPair = identityKeyPair;
        this.registrationId = registrationId;

        this.sessionsDir = new File(baseDir, "sessions");
        this.identityKeyFile = new File(baseDir, "identity.key");
        this.preKeysDir = new File(baseDir, "prekeys");
        this.signedPreKeysDir = new File(baseDir, "signed_prekeys");

        try {
            if (!baseDir.exists() && !baseDir.mkdirs()) {
                throw new IOException("Failed to create base directory: " + baseDir);
            }
            if (!sessionsDir.exists() && !sessionsDir.mkdirs()) {
                throw new IOException("Failed to create sessions directory: " + sessionsDir);
            }
            if (!preKeysDir.exists() && !preKeysDir.mkdirs()) {
                throw new IOException("Failed to create prekeys directory: " + preKeysDir);
            }
            if (!signedPreKeysDir.exists() && !signedPreKeysDir.mkdirs()) {
                throw new IOException("Failed to create signed prekeys directory: " + signedPreKeysDir);
            }

            loadIdentityKey();
            loadAllSessions();
            loadAllPreKeys();
            loadAllSignedPreKeys();
            loadTrustedIdentities();

            logger.info("SimpleFileSessionStore initialized with baseDir={}", baseDir);
        } catch (IOException e) {
            logger.error("Failed to initialize SimpleFileSessionStore", e);
            throw new RuntimeException(e);
        }
    }

    // -------- Identity Key --------

    private void loadIdentityKey() throws IOException {
        if (identityKeyFile.exists()) {
            try (DataInputStream dis = new DataInputStream(new FileInputStream(identityKeyFile))) {
                byte[] serialized = new byte[(int) identityKeyFile.length()];
                dis.readFully(serialized);
                // Deserialize identityKeyPair is tricky because IdentityKeyPair doesn't have a public constructor from bytes
                // So this example assumes the identityKeyPair was supplied externally (constructor param)
                // Alternatively, you can serialize your own IdentityKeyPair format here.
                logger.info("Identity key loaded from {}", identityKeyFile);
            }
        } else {
            // Save provided identity key to file
            try (DataOutputStream dos = new DataOutputStream(new FileOutputStream(identityKeyFile))) {
                dos.write(identityKeyPair.serialize());
                logger.info("Identity key saved to {}", identityKeyFile);
            }
        }
    }

    @Override
    public IdentityKey getIdentity(SignalProtocolAddress address) {
        String key = address.getName() + "-" + address.getDeviceId();
        return trustedKeys.get(key);
    }


    // -------- Trusted Identities --------

    private void loadTrustedIdentities() {
        // Simple implementation: trustedKeys are not persisted yet.
        // You can add persistence for trustedKeys similarly if needed.
        logger.info("Trusted identities cache initialized with {} entries", trustedKeys.size());
    }

    // -------- Sessions --------

    private File getSessionFile(SignalProtocolAddress address) {
        String filename = address.getName() + "-" + address.getDeviceId() + ".session";
        return new File(sessionsDir, filename);
    }

    private void loadAllSessions() {
        File[] files = sessionsDir.listFiles((dir, name) -> name.endsWith(".session"));
        if (files == null) return;
        for (File f : files) {
            try {
                SessionRecord record = new SessionRecord(readFileBytes(f));
                // parse SignalProtocolAddress from filename: name-deviceId.session
                String baseName = f.getName().substring(0, f.getName().length() - ".session".length());
                int sep = baseName.lastIndexOf('-');
                if (sep < 0) {
                    logger.warn("Invalid session file name (expected name-deviceId.session): {}", f.getName());
                    continue;
                }
                String name = baseName.substring(0, sep);
                int deviceId = Integer.parseInt(baseName.substring(sep + 1));
                SignalProtocolAddress addr = new SignalProtocolAddress(name, deviceId);
                sessions.put(addr, record);
                logger.debug("Loaded session for {} from {}", addr, f.getName());
            } catch (Exception e) {
                logger.error("Failed to load session file {}", f.getName(), e);
            }
        }
        logger.info("Loaded {} sessions", sessions.size());
    }

    // -------- PreKeys --------

    private File getPreKeyFile(int preKeyId) {
        return new File(preKeysDir, preKeyId + ".prekey");
    }

    private void loadAllPreKeys() {
        File[] files = preKeysDir.listFiles((dir, name) -> name.endsWith(".prekey"));
        if (files == null) return;
        for (File f : files) {
            try {
                PreKeyRecord record = new PreKeyRecord(readFileBytes(f));
                String name = f.getName();
                int preKeyId = Integer.parseInt(name.substring(0, name.length() - ".prekey".length()));
                preKeys.put(preKeyId, record);
                logger.debug("Loaded preKey {} from {}", preKeyId, f.getName());
            } catch (Exception e) {
                logger.error("Failed to load preKey file {}", f.getName(), e);
            }
        }
        logger.info("Loaded {} preKeys", preKeys.size());
    }

    // -------- Signed PreKeys --------

    private File getSignedPreKeyFile(int signedPreKeyId) {
        return new File(signedPreKeysDir, signedPreKeyId + ".signedprekey");
    }

    private void loadAllSignedPreKeys() {
        File[] files = signedPreKeysDir.listFiles((dir, name) -> name.endsWith(".signedprekey"));
        if (files == null) return;
        for (File f : files) {
            try {
                SignedPreKeyRecord record = new SignedPreKeyRecord(readFileBytes(f));
                String name = f.getName();
                int signedPreKeyId = Integer.parseInt(name.substring(0, name.length() - ".signedprekey".length()));
                signedPreKeys.put(signedPreKeyId, record);
                logger.debug("Loaded signedPreKey {} from {}", signedPreKeyId, f.getName());
            } catch (Exception e) {
                logger.error("Failed to load signedPreKey file {}", f.getName(), e);
            }
        }
        logger.info("Loaded {} signedPreKeys", signedPreKeys.size());
    }

    // -------- Utility read/write bytes --------

    private byte[] readFileBytes(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] data = new byte[(int) file.length()];
            int read = fis.read(data);
            if (read != data.length) {
                throw new IOException("Failed to read full file: " + file);
            }
            return data;
        }
    }

    private void writeFileBytes(File file, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(data);
            fos.flush();
        }
    }

    // --------------------------
    // IdentityKeyStore methods
    // --------------------------

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
        String key = address.getName() + "-" + address.getDeviceId();
        IdentityKey existing = trustedKeys.get(key);

        boolean isNew = existing == null || !existing.equals(identityKey);
        trustedKeys.put(key, identityKey);

        logger.debug("saveIdentity for {}: isNew={}", key, isNew);

        // TODO: persist trustedKeys map if needed

        return isNew;
    }

    @Override
    public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, IdentityKeyStore.Direction direction) {
        String key = address.getName() + "-" + address.getDeviceId();
        IdentityKey trusted = trustedKeys.get(key);
        boolean trustedOrUnknown = trusted == null || trusted.equals(identityKey);

        logger.debug("isTrustedIdentity for {}: result={}", key, trustedOrUnknown);
        return trustedOrUnknown;
    }

    // --------------------------
    // PreKeyStore methods
    // --------------------------

    @Override
    public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
        PreKeyRecord record = preKeys.get(preKeyId);
        if (record == null) {
            logger.error("No such preKey: {}", preKeyId);
            throw new InvalidKeyIdException("No such prekey: " + preKeyId);
        }
        try {
            return new PreKeyRecord(record.serialize());
        } catch (IOException e) {
            logger.error("Error deserializing preKeyId {}", preKeyId, e);
            throw new InvalidKeyIdException("Error deserializing prekey: " + preKeyId);
        }
    }

    @Override
    public void storePreKey(int preKeyId, PreKeyRecord record) {
        try {
            preKeys.put(preKeyId, new PreKeyRecord(record.serialize()));
            writeFileBytes(getPreKeyFile(preKeyId), record.serialize());
            logger.debug("Stored preKey {}", preKeyId);
        } catch (IOException e) {
            logger.error("Failed to store preKey {}", preKeyId, e);
        }
    }

    @Override
    public boolean containsPreKey(int preKeyId) {
        return preKeys.containsKey(preKeyId);
    }

    @Override
    public void removePreKey(int preKeyId) {
        preKeys.remove(preKeyId);
        File f = getPreKeyFile(preKeyId);
        if (f.exists() && !f.delete()) {
            logger.warn("Failed to delete preKey file {}", f);
        } else {
            logger.debug("Removed preKey {}", preKeyId);
        }
    }

    // --------------------------
    // SignedPreKeyStore methods
    // --------------------------

    @Override
    public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
        SignedPreKeyRecord record = signedPreKeys.get(signedPreKeyId);
        if (record == null) {
            logger.error("No such signedPreKey: {}", signedPreKeyId);
            throw new InvalidKeyIdException("No such signed prekey: " + signedPreKeyId);
        }
        try {
            return new SignedPreKeyRecord(record.serialize());
        } catch (IOException e) {
            logger.error("Error deserializing signedPreKeyId {}", signedPreKeyId, e);
            throw new InvalidKeyIdException("Error deserializing signed prekey: " + signedPreKeyId);
        }
    }

    @Override
    public List<SignedPreKeyRecord> loadSignedPreKeys() {
        List<SignedPreKeyRecord> list = new ArrayList<>();
        for (SignedPreKeyRecord r : signedPreKeys.values()) {
            try {
                list.add(new SignedPreKeyRecord(r.serialize()));
            } catch (IOException e) {
                logger.error("Error cloning signed prekey record", e);
            }
        }
        return list;
    }

    @Override
    public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
        try {
            signedPreKeys.put(signedPreKeyId, new SignedPreKeyRecord(record.serialize()));
            writeFileBytes(getSignedPreKeyFile(signedPreKeyId), record.serialize());
            logger.debug("Stored signedPreKey {}", signedPreKeyId);
        } catch (IOException e) {
            logger.error("Failed to store signedPreKey {}", signedPreKeyId, e);
        }
    }

    @Override
    public boolean containsSignedPreKey(int signedPreKeyId) {
        return signedPreKeys.containsKey(signedPreKeyId);
    }

    @Override
    public void removeSignedPreKey(int signedPreKeyId) {
        signedPreKeys.remove(signedPreKeyId);
        File f = getSignedPreKeyFile(signedPreKeyId);
        if (f.exists() && !f.delete()) {
            logger.warn("Failed to delete signedPreKey file {}", f);
        } else {
            logger.debug("Removed signedPreKey {}", signedPreKeyId);
        }
    }

    // --------------------------
    // SessionStore methods
    // --------------------------

    @Override
    public SessionRecord loadSession(SignalProtocolAddress address) {
        SessionRecord record = sessions.get(address);
        if (record == null) {
            return new SessionRecord();
        }
        try {
            return new SessionRecord(record.serialize());
        } catch (IOException e) {
            logger.error("Error deserializing session for {}", address, e);
            return new SessionRecord();
        }
    }

    @Override
    public List<Integer> getSubDeviceSessions(String name) {
        List<Integer> devices = new ArrayList<>();
        for (SignalProtocolAddress addr : sessions.keySet()) {
            if (addr.getName().equals(name)) {
                devices.add(addr.getDeviceId());
            }
        }
        return devices;
    }

    @Override
    public void storeSession(SignalProtocolAddress address, SessionRecord record) {
        try {
            sessions.put(address, new SessionRecord(record.serialize()));
            writeFileBytes(getSessionFile(address), record.serialize());
            logger.debug("Stored session for {}", address);
        } catch (IOException e) {
            logger.error("Failed to store session for {}", address, e);
        }
    }

    @Override
    public boolean containsSession(SignalProtocolAddress address) {
        return sessions.containsKey(address);
    }

    @Override
    public void deleteSession(SignalProtocolAddress address) {
        sessions.remove(address);
        File f = getSessionFile(address);
        if (f.exists() && !f.delete()) {
            logger.warn("Failed to delete session file {}", f);
        } else {
            logger.debug("Deleted session for {}", address);
        }
    }

    @Override
    public void deleteAllSessions(String name) {
        for (SignalProtocolAddress addr : new ArrayList<>(sessions.keySet())) {
            if (addr.getName().equals(name)) {
                deleteSession(addr);
            }
        }
    }
}
