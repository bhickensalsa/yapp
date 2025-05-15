package com.securechat.crypto.libsignal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.state.PreKeyRecord;

public class PreKeyBundleBuilder {

    private static final Logger logger = LoggerFactory.getLogger(PreKeyBundleBuilder.class);

    public static PreKeyBundle build(int registrationId, int deviceId, SignalProtocolStore store,
                                     int preKeyId, int signedPreKeyId) throws InvalidKeyException {
        PreKeyRecord preKey = null;
        SignedPreKeyRecord signedPreKey = null;

        logger.debug("Building PreKeyBundle with registrationId={}, deviceId={}, preKeyId={}, signedPreKeyId={}",
                     registrationId, deviceId, preKeyId, signedPreKeyId);

        try {
            preKey = store.loadPreKey(preKeyId);
            logger.info("Loaded PreKeyRecord for id {}", preKeyId);
        } catch (InvalidKeyIdException e) {
            logger.error("Could not load PreKeyRecord with id {}: {}", preKeyId, e.getMessage());
        }

        try {
            signedPreKey = store.loadSignedPreKey(signedPreKeyId);
            logger.info("Loaded SignedPreKeyRecord for id {}", signedPreKeyId);
        } catch (InvalidKeyIdException e) {
            logger.error("Could not load SignedPreKeyRecord with id {}: {}", signedPreKeyId, e.getMessage());
        }

        if (preKey == null || signedPreKey == null) {
            String errMsg = "PreKey or SignedPreKey not found for given IDs: preKeyId=" + preKeyId + ", signedPreKeyId=" + signedPreKeyId;
            logger.error(errMsg);
            throw new IllegalStateException(errMsg);
        }

        IdentityKey identityKey = store.getIdentityKeyPair().getPublicKey();
        logger.debug("Using identity public key for PreKeyBundle");

        PreKeyBundle bundle = new PreKeyBundle(
            registrationId,
            deviceId,
            preKeyId,
            preKey.getKeyPair().getPublicKey(),
            signedPreKeyId,
            signedPreKey.getKeyPair().getPublicKey(),
            signedPreKey.getSignature(),
            identityKey
        );

        logger.info("PreKeyBundle successfully built");
        return bundle;
    }
}
