package com.securechat.protocol.dto;

import java.util.List;

/**
 * Data Transfer Object (DTO) representing an update to the list of active users.
 *
 * <p>This DTO contains a list of users currently connected or relevant,
 * along with an update message describing the event (e.g., user connected or disconnected).
 *
 * <p>Used to communicate user list changes in the SecureChat system.
 */
public class UserListUpdateDTO {

    /** List of user information DTOs representing active or updated users */
    private List<UserInfoDTO> users;

    /** Descriptive update message, e.g., "alice connected", "bob disconnected" */
    private String updateMessage;

    /**
     * Default no-argument constructor required for deserialization.
     */
    public UserListUpdateDTO() {}

    /**
     * Constructs a new UserListUpdateDTO with the given users and update message.
     *
     * @param users         list of UserInfoDTO objects
     * @param updateMessage descriptive message about the user list update
     */
    public UserListUpdateDTO(List<UserInfoDTO> users, String updateMessage) {
        this.users = users;
        this.updateMessage = updateMessage;
    }

    /**
     * Returns the list of users associated with this update.
     *
     * @return list of UserInfoDTO objects
     */
    public List<UserInfoDTO> getUsers() {
        return users;
    }

    /**
     * Returns the descriptive update message for this user list change.
     *
     * @return update message string
     */
    public String getUpdateMessage() {
        return updateMessage;
    }
}
