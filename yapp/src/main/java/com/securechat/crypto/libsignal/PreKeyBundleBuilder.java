package com.securechat.crypto.libsignal;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.state.PreKeyRecord;

public class PreKeyBundleBuilder {

    public static PreKeyBundle build(int registrationId, int deviceId, SignalProtocolStore store,
                                 int preKeyId, int signedPreKeyId) throws InvalidKeyException {

        PreKeyRecord preKey = null;
        SignedPreKeyRecord signedPreKey = null;

        try {
            preKey = store.loadPreKey(preKeyId);
        } catch (InvalidKeyIdException e) {
            System.err.println("Could not load preKey: " + e.getMessage());
        }
        try {
            signedPreKey = store.loadSignedPreKey(signedPreKeyId);
        } catch (InvalidKeyIdException e) {
            System.err.println("Could not load signedPreKey: " + e.getMessage());
        }

        if (preKey == null || signedPreKey == null) {
            throw new IllegalStateException("PreKey or SignedPreKey not found for given IDs");
        }

        IdentityKey identityKey = store.getIdentityKeyPair().getPublicKey();

        return new PreKeyBundle(
            registrationId,
            deviceId,
            preKeyId,
            preKey.getKeyPair().getPublicKey(),
            signedPreKeyId,
            signedPreKey.getKeyPair().getPublicKey(),
            signedPreKey.getSignature(),
            identityKey
        );
    }
}
