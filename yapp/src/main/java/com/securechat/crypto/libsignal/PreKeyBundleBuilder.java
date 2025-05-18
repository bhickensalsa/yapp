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

public class PreKeyBundleBuilder {

    private static final Logger logger = LoggerFactory.getLogger(PreKeyBundleBuilder.class);

    public static PreKeyBundle build(int registrationId, int deviceId, SignalProtocolStore store,
                                     int preKeyId, int signedPreKeyId) throws InvalidKeyException {

        logger.debug("Building PreKeyBundle with registrationId={}, deviceId={}, preKeyId={}, signedPreKeyId={}",
                     registrationId, deviceId, preKeyId, signedPreKeyId);

        PreKeyRecord preKey;
        SignedPreKeyRecord signedPreKey;

        try {
            preKey = store.loadPreKey(preKeyId);
            logger.info("Loaded PreKeyRecord for ID: {}", preKeyId);
        } catch (InvalidKeyIdException e) {
            String message = String.format("Failed to load PreKey with ID %d: %s", preKeyId, e.getMessage());
            logger.error(message);
            throw new IllegalStateException(message, e);
        }

        try {
            signedPreKey = store.loadSignedPreKey(signedPreKeyId);
            logger.info("Loaded SignedPreKeyRecord for ID: {}", signedPreKeyId);
        } catch (InvalidKeyIdException e) {
            String message = String.format("Failed to load SignedPreKey with ID %d: %s", signedPreKeyId, e.getMessage());
            logger.error(message);
            throw new IllegalStateException(message, e);
        }

        IdentityKey identityKey = store.getIdentityKeyPair().getPublicKey();
        if (identityKey == null) {
            String errMsg = "IdentityKey is null; ensure user identity is initialized properly";
            logger.error(errMsg);
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

        logger.info("PreKeyBundle successfully built for deviceId {}", deviceId);
        return bundle;
    }
}
