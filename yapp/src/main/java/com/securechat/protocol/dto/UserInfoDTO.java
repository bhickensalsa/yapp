package com.securechat.protocol.dto;

/**
 * Data Transfer Object (DTO) representing basic user information.
 *
 * <p>Contains the user ID and device ID, commonly used for identifying
 * a specific device associated with a user in the SecureChat system.
 *
 * <p>This class supports serialization/deserialization for network communication.
 */
public class UserInfoDTO {

    /** Unique identifier for the user */
    private String userId;

    /** Identifier for the user's device */
    private int deviceId;

    /**
     * Default no-argument constructor required for deserialization.
     */
    public UserInfoDTO() {}

    /**
     * Constructs a new UserInfoDTO with the specified user ID and device ID.
     *
     * @param userId   the user ID
     * @param deviceId the device ID
     */
    public UserInfoDTO(String userId, int deviceId) {
        this.userId = userId;
        this.deviceId = deviceId;
    }

    /**
     * Returns the user ID.
     *
     * @return the user ID string
     */
    public String getUserId() {
        return userId;
    }

    /**
     * Returns the device ID.
     *
     * @return the device ID integer
     */
    public int getDeviceId() {
        return deviceId;
    }
}
