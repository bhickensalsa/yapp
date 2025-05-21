package com.securechat.protocol.dto;

import com.google.gson.Gson;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.state.PreKeyBundle;

import java.io.Serializable;
import java.util.Base64;

/**
 * Data Transfer Object (DTO) for serializing and deserializing {@link PreKeyBundle}
 * objects to JSON or across network boundaries. Converts complex LibSignal objects
 * into a simplified, Base64-encoded representation suitable for transport.
 *
 * <p>Provides functionality to:
 * <ul>
 *     <li>Convert a {@link PreKeyBundle} to a DTO</li>
 *     <li>Convert a DTO back into a {@link PreKeyBundle}</li>
 *     <li>Serialize/deserialize the DTO as JSON</li>
 * </ul>
 *
 * <p>Note: All key-related fields are encoded in Base64 to ensure safe transport over potential text-based protocols.
 *
 * @author bhickensalsa
 * @version 0.1
 */
public class PreKeyBundleDTO implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger logger = LoggerFactory.getLogger(PreKeyBundleDTO.class);
    private static final String LOG_PREFIX = "[PreKeyBundleDTO]";
    private static final Gson gson = new Gson();

    private int registrationId;
    private int deviceId;
    private int preKeyId;
    private String preKeyPublic;             // Base64-encoded public key
    private int signedPreKeyId;
    private String signedPreKeyPublic;       // Base64-encoded signed public key
    private String signedPreKeySignature;    // Base64-encoded signature
    private String identityKey;              // Base64-encoded identity key

    /**
     * Converts a {@link PreKeyBundle} object into a {@link PreKeyBundleDTO}.
     *
     * @param bundle the PreKeyBundle to convert
     * @return a DTO representing the bundle
     */
    public static PreKeyBundleDTO fromPreKeyBundle(PreKeyBundle bundle) {
        logger.debug("{} Converting PreKeyBundle to DTO for registrationId={}, deviceId={}",
                LOG_PREFIX, bundle.getRegistrationId(), bundle.getDeviceId());

        PreKeyBundleDTO dto = new PreKeyBundleDTO();
        dto.setRegistrationId(bundle.getRegistrationId());
        dto.setDeviceId(bundle.getDeviceId());
        dto.setPreKeyId(bundle.getPreKeyId());
        dto.setPreKeyPublic(Base64.getEncoder().encodeToString(bundle.getPreKey().serialize()));
        dto.setSignedPreKeyId(bundle.getSignedPreKeyId());
        dto.setSignedPreKeyPublic(Base64.getEncoder().encodeToString(bundle.getSignedPreKey().serialize()));
        dto.setSignedPreKeySignature(Base64.getEncoder().encodeToString(bundle.getSignedPreKeySignature()));
        dto.setIdentityKey(Base64.getEncoder().encodeToString(bundle.getIdentityKey().serialize()));

        logger.info("{} PreKeyBundleDTO created successfully", LOG_PREFIX);
        return dto;
    }

    /**
     * Converts this DTO back into a {@link PreKeyBundle} object.
     *
     * @return the reconstructed PreKeyBundle
     * @throws RuntimeException if conversion fails due to malformed or missing fields
     */
    public PreKeyBundle toPreKeyBundle() {
        logger.debug("{} Converting DTO to PreKeyBundle for registrationId={}, deviceId={}", LOG_PREFIX, registrationId, deviceId);
        try {
            validateFields();

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
            logger.error("{} Failed to convert DTO to PreKeyBundle", LOG_PREFIX, e);
            throw new RuntimeException("Failed to convert DTO to PreKeyBundle", e);
        }
    }

    /**
     * Serializes this DTO to a JSON string.
     *
     * @return the JSON representation of this DTO
     */
    public String toJson() {
        logger.debug("{} Serializing PreKeyBundleDTO to JSON", LOG_PREFIX);
        return gson.toJson(this);
    }

    /**
     * Deserializes a JSON string into a {@link PreKeyBundleDTO} object.
     *
     * @param json the JSON string to parse
     * @return the deserialized DTO
     * @throws RuntimeException if JSON parsing fails
     */
    public static PreKeyBundleDTO fromJson(String json) {
        logger.debug("{} Deserializing JSON to PreKeyBundleDTO", LOG_PREFIX);
        try {
            return gson.fromJson(json, PreKeyBundleDTO.class);
        } catch (Exception e) {
            logger.error("{} Failed to deserialize JSON to PreKeyBundleDTO", LOG_PREFIX, e);
            throw e;
        }
    }

    /**
     * Validates that all required fields for a {@link PreKeyBundle} are present.
     *
     * @throws IllegalStateException if any field is null
     */
    private void validateFields() {
        if (preKeyPublic == null || signedPreKeyPublic == null ||
            signedPreKeySignature == null || identityKey == null) {
            throw new IllegalStateException("Missing field(s) in PreKeyBundleDTO");
        }
    }

    @Override
    public String toString() {
        return "PreKeyBundleDTO{" +
                "registrationId=" + registrationId +
                ", deviceId=" + deviceId +
                ", preKeyId=" + preKeyId +
                ", signedPreKeyId=" + signedPreKeyId +
                '}';
    }

    // Getters and Setters

    public int getRegistrationId() {
        return registrationId;
    }

    public void setRegistrationId(int registrationId) {
        this.registrationId = registrationId;
    }

    public int getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(int deviceId) {
        this.deviceId = deviceId;
    }

    public int getPreKeyId() {
        return preKeyId;
    }

    public void setPreKeyId(int preKeyId) {
        this.preKeyId = preKeyId;
    }

    public String getPreKeyPublic() {
        return preKeyPublic;
    }

    public void setPreKeyPublic(String preKeyPublic) {
        this.preKeyPublic = preKeyPublic;
    }

    public int getSignedPreKeyId() {
        return signedPreKeyId;
    }

    public void setSignedPreKeyId(int signedPreKeyId) {
        this.signedPreKeyId = signedPreKeyId;
    }

    public String getSignedPreKeyPublic() {
        return signedPreKeyPublic;
    }

    public void setSignedPreKeyPublic(String signedPreKeyPublic) {
        this.signedPreKeyPublic = signedPreKeyPublic;
    }

    public String getSignedPreKeySignature() {
        return signedPreKeySignature;
    }

    public void setSignedPreKeySignature(String signedPreKeySignature) {
        this.signedPreKeySignature = signedPreKeySignature;
    }

    public String getIdentityKey() {
        return identityKey;
    }

    public void setIdentityKey(String identityKey) {
        this.identityKey = identityKey;
    }
}
