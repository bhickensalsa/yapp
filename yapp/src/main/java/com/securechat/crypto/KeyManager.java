package com.securechat.crypto;

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

    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Generates a new IdentityKeyPair (long-term identity key pair).
     */
    public IdentityKeyPair generateIdentityKeyPair() {
        ECKeyPair ecKeyPair = Curve.generateKeyPair();
        IdentityKey identityKey = new IdentityKey(ecKeyPair.getPublicKey());
        ECPrivateKey privateKey = ecKeyPair.getPrivateKey();
        return new IdentityKeyPair(identityKey, privateKey);
    }

    /**
     * Generates a unique registration ID (1 to 16380).
     */
    public int generateRegistrationId() {
        return secureRandom.nextInt(16380) + 1;
    }

    /**
     * Generates a new PreKeyRecord with the given ID.
     */
    public PreKeyRecord generatePreKey(int id) {
        ECKeyPair keyPair = Curve.generateKeyPair();
        return new PreKeyRecord(id, keyPair);
    }

    /**
     * Generates a SignedPreKeyRecord signed by the identity key pair.
     */
    public SignedPreKeyRecord generateSignedPreKey(IdentityKeyPair identityKeyPair, int id) {
        try {
            ECKeyPair signedPreKeyPair = Curve.generateKeyPair();
            byte[] dataToSign = signedPreKeyPair.getPublicKey().serialize();
            ECPrivateKey privateKey = identityKeyPair.getPrivateKey();
            byte[] signature = Curve.calculateSignature(privateKey, dataToSign);
            long timestamp = System.currentTimeMillis();

            return new SignedPreKeyRecord(id, timestamp, signedPreKeyPair, signature);

        } catch (InvalidKeyException e) {
            throw new RuntimeException("Failed to generate signed pre key", e);
        }
    }
}
