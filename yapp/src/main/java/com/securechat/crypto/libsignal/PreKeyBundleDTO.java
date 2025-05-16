package com.securechat.crypto.libsignal;

import com.google.gson.Gson;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.state.PreKeyBundle;

import java.io.Serializable;
import java.util.Base64;

public class PreKeyBundleDTO implements Serializable {
    private static final Logger logger = LoggerFactory.getLogger(PreKeyBundleDTO.class);

    public int registrationId;
    public int deviceId;
    public int preKeyId;
    public String preKeyPublic; // Base64
    public int signedPreKeyId;
    public String signedPreKeyPublic; // Base64
    public String signedPreKeySignature; // Base64
    public String identityKey; // Base64

    public static PreKeyBundleDTO fromPreKeyBundle(PreKeyBundle bundle) {
        logger.debug("Converting PreKeyBundle to DTO for registrationId={}, deviceId={}", 
                     bundle.getRegistrationId(), bundle.getDeviceId());
        PreKeyBundleDTO dto = new PreKeyBundleDTO();
        dto.registrationId = bundle.getRegistrationId();
        dto.deviceId = bundle.getDeviceId();
        dto.preKeyId = bundle.getPreKeyId();
        dto.preKeyPublic = Base64.getEncoder().encodeToString(bundle.getPreKey().serialize());
        dto.signedPreKeyId = bundle.getSignedPreKeyId();
        dto.signedPreKeyPublic = Base64.getEncoder().encodeToString(bundle.getSignedPreKey().serialize());
        dto.signedPreKeySignature = Base64.getEncoder().encodeToString(bundle.getSignedPreKeySignature());
        dto.identityKey = Base64.getEncoder().encodeToString(bundle.getIdentityKey().serialize());
        logger.info("PreKeyBundleDTO created successfully");
        return dto;
    }

    public PreKeyBundle toPreKeyBundle() {
        logger.debug("Converting DTO to PreKeyBundle for registrationId={}, deviceId={}", registrationId, deviceId);
        try {
            PreKeyBundle bundle = new PreKeyBundle(
                registrationId,
                deviceId,
                preKeyId,
                Curve.decodePoint(Base64.getDecoder().decode(preKeyPublic), 0),
                signedPreKeyId,
                Curve.decodePoint(Base64.getDecoder().decode(signedPreKeyPublic), 0),
                Base64.getDecoder().decode(signedPreKeySignature),
                new IdentityKey(Base64.getDecoder().decode(identityKey), 0)
            );
            logger.info("PreKeyBundle conversion successful");
            return bundle;
        } catch (Exception e) {
            logger.error("Failed to convert DTO to PreKeyBundle", e);
            throw new RuntimeException("Failed to convert DTO to PreKeyBundle", e);
        }
    }

    public String toJson() {
        logger.debug("Serializing PreKeyBundleDTO to JSON");
        String json = new Gson().toJson(this);
        logger.info("Serialization to JSON completed");
        return json;
    }

    public static PreKeyBundleDTO fromJson(String json) {
        logger.debug("Deserializing JSON to PreKeyBundleDTO");
        try {
            PreKeyBundleDTO dto = new Gson().fromJson(json, PreKeyBundleDTO.class);
            logger.info("Deserialization from JSON successful");
            return dto;
        } catch (Exception e) {
            logger.error("Failed to deserialize JSON to PreKeyBundleDTO", e);
            throw e;
        }
    }
}
