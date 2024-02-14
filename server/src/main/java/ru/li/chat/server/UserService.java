package ru.li.chat.server;

import java.time.OffsetDateTime;

public interface UserService {
    String getUsernameByLoginAndPassword(String login, String password);

    String getUserRolesByUsername(String username);

    OffsetDateTime getUserBanTime(String username);

    boolean isUsernameExists(String username);

    boolean isLoginAlreadyExists(String login);

    boolean isUserAdmin(String username);

    boolean isUserHasRole(String username, String roleName);

    boolean isUserHasOneRole(String username);

    boolean isUserLastAdmin(String username);

    void createNewUser(String username, String login, String password, UserRole role);

    void addRole(String username, String roleName);

    void removeRole(String username, String roleName);

    boolean changeUsername(String username, String newUsername);

    void banUser(String username, OffsetDateTime banTime);
}
