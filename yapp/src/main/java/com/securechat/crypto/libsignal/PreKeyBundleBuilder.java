package com.securechat.crypto.libsignal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;

/**
 * Utility class for constructing {@link PreKeyBundle} instances from a given
 * {@link SignalProtocolStore} using specified pre-key and signed pre-key IDs.
 *
 * <p>This builder loads the necessary key records from the store, validates the
 * presence of the user's identity key, and combines these elements into a
 * {@link PreKeyBundle} suitable for distribution or session establishment.
 * 
 * @author bhickensalsa
 * @version 0.1
 */
public class PreKeyBundleBuilder {

    private static final Logger logger = LoggerFactory.getLogger(PreKeyBundleBuilder.class);
    private static final String LOG_PREFIX = "[PreKeyBundleBuilder]";

    /**
     * Builds a {@link PreKeyBundle} for the specified registration and device IDs
     * by retrieving the pre-key and signed pre-key records from the given
     * {@link SignalProtocolStore}.
     *
     * <p>Throws an {@link IllegalStateException} if the pre-key or signed pre-key
     * cannot be loaded, or if the identity key is not initialized in the store.
     *
     * @param registrationId The registration ID of the user/device
     * @param deviceId The device ID
     * @param store The {@link SignalProtocolStore} containing key records
     * @param preKeyId The ID of the pre-key record to load
     * @param signedPreKeyId The ID of the signed pre-key record to load
     * @return A fully constructed {@link PreKeyBundle} with keys and signatures
     * @throws InvalidKeyException If the keys are invalid or corrupted
     * @throws IllegalStateException If keys cannot be loaded or identity key is missing
     */
    public static PreKeyBundle build(int registrationId, int deviceId, SignalProtocolStore store,
                                     int preKeyId, int signedPreKeyId) throws InvalidKeyException {

        logger.debug("{} Building PreKeyBundle with registrationId={}, deviceId={}, preKeyId={}, signedPreKeyId={}",
                     LOG_PREFIX, registrationId, deviceId, preKeyId, signedPreKeyId);

        PreKeyRecord preKey;
        SignedPreKeyRecord signedPreKey;

        try {
            preKey = store.loadPreKey(preKeyId);
            logger.info("{} Loaded PreKeyRecord for ID: {}", LOG_PREFIX, preKeyId);
        } catch (InvalidKeyIdException e) {
            String message = String.format("Failed to load PreKey with ID %d: %s", preKeyId, e.getMessage());
            logger.error("{} {}", LOG_PREFIX, message);
            throw new IllegalStateException(message, e);
        }

        try {
            signedPreKey = store.loadSignedPreKey(signedPreKeyId);
            logger.info("{} Loaded SignedPreKeyRecord for ID: {}", LOG_PREFIX, signedPreKeyId);
        } catch (InvalidKeyIdException e) {
            String message = String.format("Failed to load SignedPreKey with ID %d: %s", signedPreKeyId, e.getMessage());
            logger.error("{} {}", LOG_PREFIX, message);
            throw new IllegalStateException(message, e);
        }

        IdentityKey identityKey = store.getIdentityKeyPair().getPublicKey();
        if (identityKey == null) {
            String errMsg = "IdentityKey is null; ensure user identity is initialized properly";
            logger.error("{} {}", LOG_PREFIX, errMsg);
            throw new IllegalStateException(errMsg);
        }

        PreKeyBundle bundle = new PreKeyBundle(
            registrationId,
            deviceId,
            preKey.getId(),
            preKey.getKeyPair().getPublicKey(),
            signedPreKey.getId(),
            signedPreKey.getKeyPair().getPublicKey(),
            signedPreKey.getSignature(),
            identityKey
        );

        logger.info("{} PreKeyBundle successfully built for deviceId {}", LOG_PREFIX, deviceId);
        return bundle;
    }
}
