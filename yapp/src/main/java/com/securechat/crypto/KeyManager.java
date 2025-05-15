package com.securechat.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;

import java.security.SecureRandom;

public class KeyManager {

    private static final Logger logger = LoggerFactory.getLogger(KeyManager.class);
    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Generates a new IdentityKeyPair (long-term identity key pair).
     */
    public IdentityKeyPair generateIdentityKeyPair() {
        logger.debug("Generating new IdentityKeyPair");
        ECKeyPair ecKeyPair = Curve.generateKeyPair();
        IdentityKey identityKey = new IdentityKey(ecKeyPair.getPublicKey());
        ECPrivateKey privateKey = ecKeyPair.getPrivateKey();
        IdentityKeyPair identityKeyPair = new IdentityKeyPair(identityKey, privateKey);
        logger.info("Generated IdentityKeyPair");
        return identityKeyPair;
    }

    /**
     * Generates a unique registration ID (1 to 16380).
     */
    public int generateRegistrationId() {
        int regId = secureRandom.nextInt(16380) + 1;
        logger.debug("Generated registration ID: {}", regId);
        return regId;
    }

    /**
     * Generates a new PreKeyRecord with the given ID.
     */
    public PreKeyRecord generatePreKey(int id) {
        logger.debug("Generating PreKeyRecord with id {}", id);
        PreKeyRecord preKey = new PreKeyRecord(id, Curve.generateKeyPair());
        logger.info("Generated PreKeyRecord with id {}", id);
        return preKey;
    }

    /**
     * Generates a SignedPreKeyRecord signed by the identity key pair.
     */
    public SignedPreKeyRecord generateSignedPreKey(IdentityKeyPair identityKeyPair, int id) {
        logger.debug("Generating SignedPreKeyRecord with id {}", id);
        try {
            ECKeyPair signedPreKeyPair = Curve.generateKeyPair();
            byte[] dataToSign = signedPreKeyPair.getPublicKey().serialize();
            ECPrivateKey privateKey = identityKeyPair.getPrivateKey();
            byte[] signature = Curve.calculateSignature(privateKey, dataToSign);
            long timestamp = System.currentTimeMillis();

            SignedPreKeyRecord signedPreKeyRecord = new SignedPreKeyRecord(id, timestamp, signedPreKeyPair, signature);
            logger.info("Generated SignedPreKeyRecord with id {}", id);
            return signedPreKeyRecord;

        } catch (InvalidKeyException e) {
            logger.error("Failed to generate signed pre key with id {}", id, e);
            throw new RuntimeException("Failed to generate signed pre key", e);
        }
    }
}
