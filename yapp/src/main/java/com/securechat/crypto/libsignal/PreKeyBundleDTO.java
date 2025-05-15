package com.securechat.crypto.libsignal;

import com.google.gson.Gson;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.state.PreKeyBundle;

import java.util.Base64;

public class PreKeyBundleDTO {
    public int registrationId;
    public int deviceId;
    public int preKeyId;
    public String preKeyPublic; // Base64
    public int signedPreKeyId;
    public String signedPreKeyPublic; // Base64
    public String signedPreKeySignature; // Base64
    public String identityKey; // Base64

    public static PreKeyBundleDTO fromPreKeyBundle(PreKeyBundle bundle) {
        PreKeyBundleDTO dto = new PreKeyBundleDTO();
        dto.registrationId = bundle.getRegistrationId();
        dto.deviceId = bundle.getDeviceId();
        dto.preKeyId = bundle.getPreKeyId();
        dto.preKeyPublic = Base64.getEncoder().encodeToString(bundle.getPreKey().serialize());
        dto.signedPreKeyId = bundle.getSignedPreKeyId();
        dto.signedPreKeyPublic = Base64.getEncoder().encodeToString(bundle.getSignedPreKey().serialize());
        dto.signedPreKeySignature = Base64.getEncoder().encodeToString(bundle.getSignedPreKeySignature());
        dto.identityKey = Base64.getEncoder().encodeToString(bundle.getIdentityKey().serialize());
        return dto;
    }

    public PreKeyBundle toPreKeyBundle() {
        try {
            return new PreKeyBundle(
                registrationId,
                deviceId,
                preKeyId,
                Curve.decodePoint(Base64.getDecoder().decode(preKeyPublic), 0),
                signedPreKeyId,
                Curve.decodePoint(Base64.getDecoder().decode(signedPreKeyPublic), 0),
                Base64.getDecoder().decode(signedPreKeySignature),
                new IdentityKey(Base64.getDecoder().decode(identityKey), 0)
            );
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert DTO to PreKeyBundle", e);
        }
    }

    public String toJson() {
        return new Gson().toJson(this);
    }

    public static PreKeyBundleDTO fromJson(String json) {
        return new Gson().fromJson(json, PreKeyBundleDTO.class);
    }
}
