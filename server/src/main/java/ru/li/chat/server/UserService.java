package ru.li.chat.server;

public interface UserService {
    String getUsernameByLoginAndPassword(String login, String password);
    boolean isUsernameAlreadyExists(String username);
    boolean isLoginAlreadyExists(String login);
    boolean isUserAdmin(String username);
    void createNewUser(String username, String login, String password, UserRole role);
    void addRoleToUser(String username, UserRole role);
    void removeRoleFromUser(String username, UserRole role);
    boolean changeUsername(String username, String newUsername);
}
