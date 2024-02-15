package ru.li.chat.server;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.sql.*;
import java.time.OffsetDateTime;
import java.util.*;

public class InDataBaseUserService implements UserService {
    static class User {
        private String username;
        private final String login;
        private final String password;
        private final String salt;
        private OffsetDateTime banTime;
        private Set<UserRole> roles;

        public User(String username, String login, String password, String salt, Set<UserRole> roles) {
            this.username = username;
            this.login = login;
            this.password = password;
            this.salt = salt;
            this.roles = roles;
        }

        public User(String username, String login, String password, String salt, OffsetDateTime banTime, Set<UserRole> roles) {
            this.username = username;
            this.login = login;
            this.password = password;
            this.salt = salt;
            this.banTime = banTime;
            this.roles = roles;
        }

        @Override
        public String toString() {
            return "User{" +
                    ", username='" + username + '\'' +
                    ", login='" + login + '\'' +
                    ", banTime='" + banTime + '\'' +
                    ", roles=" + roles +
                    '}';
        }
    }

    private static final String DATABASE_URL = "jdbc:postgresql://localhost:5432/UserService";
    private static final String LOGIN = "postgres";
    private static final String PASSWORD = "123456";
    private final List<User> users;
    private final Logger logger = LogManager.getLogger(InDataBaseUserService.class.getName());

    public InDataBaseUserService() {
        this.users = new ArrayList<>();
        fillUsers();
    }

    private void fillUsers() {
        logger.debug("fillUsers - подключение к базе данных");
        try (Connection connection = DriverManager.getConnection(DATABASE_URL, LOGIN, PASSWORD)) {
            getUsersFromDatabase(connection);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private void getUsersFromDatabase(Connection connection) throws SQLException {
        logger.debug("getUsersFromDatabase - получение соединение");
        try (Statement statement = connection.createStatement()) {
            executeQueryForGetUsersFromDatabase(statement);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    private void executeQueryForGetUsersFromDatabase(Statement statement) throws SQLException {
        String sqlQuery = "SELECT u.user_id, u.user_name, u.login, u.password, u.salt, u.ban_time, r.role_name FROM UserToRole utr JOIN Users u ON utr.user_id = u.user_id JOIN Roles r ON utr.role_id = r.role_id";
        logger.debug("executeQueryForGetUsersFromDatabase - получение результата запроса: " + sqlQuery);
        try (ResultSet resultSet = statement.executeQuery(sqlQuery)) {
            Map<Integer, User> idToUsersData = new HashMap<>(); // Для сохранения данных о пользователях
            Map<Integer, Set<UserRole>> idToRole = new HashMap<>(); // Для сохранения ролей пользователей
            while (resultSet.next()) {
                int userId = resultSet.getInt(1);
                String userName = resultSet.getString(2);
                String login = resultSet.getString(3);
                String password = resultSet.getString(4);
                String salt = resultSet.getString(5);
                OffsetDateTime banTime = resultSet.getObject(6, OffsetDateTime.class);
                String roleName = resultSet.getString(7);
                // Данные о пользователях
                if (!idToUsersData.containsKey(userId)) {
                    User user = new User(userName, login, password, salt, banTime, new HashSet<>());
                    idToUsersData.put(userId, user);
                    logger.debug("executeQueryForGetUsersFromDatabase - создался пользователь: " + user);
                }
                // Данные о ролях
                if (idToRole.containsKey(userId)) {
                    Set<UserRole> userRoles = idToRole.get(userId);
                    userRoles.add(UserRole.valueOf(roleName));
                } else {
                    Set<UserRole> userRoles = new HashSet<>();
                    userRoles.add(UserRole.valueOf(roleName));
                    idToRole.put(userId, userRoles);
                }
            }
            // Обработаем случай первого запуска, если ещё нет пользователей, то создадим admin/admin
            if (idToUsersData.isEmpty()) {
                createNewUser("admin", "admin", getDefaultPasswordForAdmin(), UserRole.ADMIN);
                executeQueryForGetUsersFromDatabase(statement); // рекурсивно вызовем для получения данных
            }
            // Заполним роли
            for (int userId : idToUsersData.keySet()) {
                User user = idToUsersData.get(userId);
                user.roles = idToRole.getOrDefault(userId, new HashSet<>());
                this.users.add(user);
                logger.debug("executeQueryForGetUsersFromDatabase - заполнились роли: " + user);
            }
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    @Override
    public String getUsernameByLoginAndPassword(String login, String password) {
        User userByLogin = null;
        for (User user : users) {
            if (user.login.equals(login)) {
                userByLogin = user;
                break;
            }
        }
        if (userByLogin == null) {
            return null;
        }
        byte[] salt = decodeToByteArray(userByLogin.salt);
        String hashedPassword = getHashString(password, salt);
        if (userByLogin.password.equals(hashedPassword)) {
            return userByLogin.username;
        }
        return null;
    }

    @Override
    public String getUserInfo(String username) {
        return getUserByUsername(username).toString();
    }

    @Override
    public OffsetDateTime getUserBanTime(String username) {
        User user = getUserByUsername(username);
        return user.banTime;
    }

    @Override
    public boolean isUsernameExists(String username) {
        for (User user : users) {
            if (user.username.equals(username)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean isLoginAlreadyExists(String login) {
        for (User user : users) {
            if (user.login.equals(login)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean isUserAdmin(String username) {
        for (User user : users) {
            if (user.username.equals(username) && user.roles.contains(UserRole.ADMIN)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void createNewUser(String username, String login, String password, UserRole role) {
        byte[] salt = getSalt();
        String saltString = encodeToString(salt);
        String hashedPassword = getHashString(password, salt);
        logger.debug("createNewUser - подключение к базе данных");
        try (Connection connection = DriverManager.getConnection(DATABASE_URL, LOGIN, PASSWORD)) {
            connection.setAutoCommit(false);
            insertIntoUsers(username, login, hashedPassword, saltString, connection);
            insertIntoUserToRole(login, role.toString(), connection);
            connection.setAutoCommit(true);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
        User user = new User(username, login, hashedPassword, saltString, new HashSet<>(List.of(role)));
        this.users.add(user);
        logger.info("Зарегистрирован новый пользователь: " + user);
    }

    private void insertIntoUserToRole(String login, String roleName, Connection connection) throws SQLException {
        int userId = getUserIdByLogin(login, connection);
        int roleId = getRoleIdByRoleName(roleName, connection);
        String sqlQuery = "INSERT INTO UserToRole (user_id, role_id) values (?, ?)";
        logger.debug("insertIntoUserToRole - получение preparedStatement по запросу: " + sqlQuery);
        try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery)) {
            preparedStatement.setInt(1, userId);
            preparedStatement.setInt(2, roleId);
            logger.debug("insertIntoUserToRole - выполнение preparedStatement: " + preparedStatement);
            preparedStatement.executeUpdate();
        } catch (SQLException | RuntimeException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    private void insertIntoUsers(String username, String login, String password, String salt, Connection connection) throws SQLException {
        String sqlQuery = "INSERT INTO Users (user_name, login, password, salt) values (?, ?, ?, ?)";
        logger.debug("insertIntoUsers - получение preparedStatement по запросу: " + sqlQuery);
        try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery)) {
            preparedStatement.setString(1, username);
            preparedStatement.setString(2, login);
            preparedStatement.setString(3, password);
            preparedStatement.setString(4, salt);
            logger.debug("insertIntoUsers - выполнение preparedStatement: " + preparedStatement);
            preparedStatement.executeUpdate();
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    private int getRoleIdByRoleName(String roleName, Connection connection) throws SQLException {
        String sqlQuery = "SELECT r.role_id FROM Roles r WHERE r.role_name = ?";
        logger.debug("getRoleIdByRoleName - получение preparedStatement по запросу: " + sqlQuery);
        try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery)) {
            preparedStatement.setString(1, roleName);
            return executeQueryForGetRoleIdByRoleName(roleName, preparedStatement, connection);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    private int executeQueryForGetRoleIdByRoleName(String roleName, PreparedStatement preparedStatement, Connection connection) throws SQLException {
        logger.debug("executeQueryForGetRoleIdByRoleName - выполнение preparedStatement: " + preparedStatement);
        try (ResultSet resultSet = preparedStatement.executeQuery()) {
            if (!resultSet.next()) {
                createNewRole(roleName, connection);
                return getRoleIdByRoleName(roleName, connection);
            }
            return resultSet.getInt(1);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    private void createNewRole(String roleName, Connection connection) throws SQLException {
        String sqlQuery = "INSERT INTO Roles (role_name) values (?)";
        logger.debug("createNewRole - получение preparedStatement по запросу: " + sqlQuery);
        try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery)) {
            preparedStatement.setString(1, roleName);
            logger.debug("createNewRole - выполнение preparedStatement: " + preparedStatement);
            preparedStatement.executeUpdate();
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    private int getUserIdByLogin(String login, Connection connection) throws SQLException {
        String sqlQuery = "SELECT u.user_id FROM Users u WHERE u.login = ?";
        logger.debug("getUserIdByLogin - получение preparedStatement по запросу: " + sqlQuery);
        try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery)) {
            preparedStatement.setString(1, login);
            return executeQueryForGetUserIdByLogin(preparedStatement);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    private int executeQueryForGetUserIdByLogin(PreparedStatement preparedStatement) throws SQLException {
        logger.debug("executeQueryForGetUserIdByLogin - выполнение preparedStatement: " + preparedStatement);
        try (ResultSet resultSet = preparedStatement.executeQuery()) {
            resultSet.next();
            return resultSet.getInt(1);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    @Override
    public void addRole(String username, String roleName) {
        User user = getUserByUsername(username);
        logger.debug("addRole - подключение к базе данных");
        try (Connection connection = DriverManager.getConnection(DATABASE_URL, LOGIN, PASSWORD)) {
            insertIntoUserToRole(user.login, roleName, connection);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
        user.roles.add(UserRole.valueOf(roleName));
    }

    @Override
    public void removeRole(String username, String roleName) {
        User user = getUserByUsername(username);
        logger.debug("removeRole - подключение к базе данных");
        try (Connection connection = DriverManager.getConnection(DATABASE_URL, LOGIN, PASSWORD)) {
            deleteFromUserToRole(user.login, roleName, connection);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
        user.roles.remove(UserRole.valueOf(roleName));
    }

    private void deleteFromUserToRole(String login, String roleName, Connection connection) throws SQLException {
        int userId = getUserIdByLogin(login, connection);
        int roleId = getRoleIdByRoleName(roleName, connection);
        String sqlQuery = "DELETE FROM UserToRole WHERE user_id = ? and role_id = ?";
        logger.debug("deleteFromUserToRole - получение preparedStatement по запросу: " + sqlQuery);
        try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery)) {
            preparedStatement.setInt(1, userId);
            preparedStatement.setInt(2, roleId);
            logger.debug("deleteFromUserToRole - выполнение preparedStatement: " + preparedStatement);
            preparedStatement.executeUpdate();
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    @Override
    public boolean changeUsername(String currentUsername, String newUsername) {
        User currentUser = null;
        for (User user : users) {
            if (user.username.equals(currentUsername)) {
                currentUser = user;
            }
        }
        if (currentUser == null) {
            logger.error("Не найден пользователь при смене ника: " + currentUsername);
            return false;
        }
        changeUsernameInDataBase(currentUser.login, newUsername);
        currentUser.username = newUsername;
        return true;
    }

    @Override
    public void banUser(String username, OffsetDateTime banTime) {
        User user = getUserByUsername(username);
        logger.debug("banUser - подключение к базе данных");
        try (Connection connection = DriverManager.getConnection(DATABASE_URL, LOGIN, PASSWORD)) {
            int userId = getUserIdByLogin(user.login, connection);
            updateUserBanTime(userId, banTime, connection);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
        user.banTime = banTime;
    }

    private void updateUserBanTime(int userId, OffsetDateTime banTime, Connection connection) throws SQLException {
        String sqlQuery = "UPDATE Users SET ban_time = ? WHERE user_id = ?";
        logger.debug("updateUserBanTime - получение preparedStatement по запросу: " + sqlQuery);
        try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery)) {
            preparedStatement.setObject(1, banTime);
            preparedStatement.setInt(2, userId);
            logger.debug("updateUserBanTime - выполнение preparedStatement: " + preparedStatement);
            preparedStatement.executeUpdate();
        }
    }

    @Override
    public boolean isUserHasRole(String username, String roleName) {
        User user = getUserByUsername(username);
        return user.roles.contains(UserRole.valueOf(roleName));
    }

    @Override
    public boolean isUserHasOneRole(String username) {
        User user = getUserByUsername(username);
        return user.roles.size() == 1;
    }

    @Override
    public boolean isUserLastAdmin(String username) {
        for (User user : users) {
            if (user.roles.contains(UserRole.ADMIN) && !user.username.equals(username)) {
                return false;
            }
        }
        return true;
    }

    private void changeUsernameInDataBase(String login, String newUsername) {
        logger.debug("changeUsernameInDataBase - подключение к базе данных");
        try (Connection connection = DriverManager.getConnection(DATABASE_URL, LOGIN, PASSWORD)) {
            int userId = getUserIdByLogin(login, connection);
            setNewUsernameByUserId(userId, newUsername, connection);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private void setNewUsernameByUserId(int userId, String newUsername, Connection connection) throws SQLException {
        String sqlQuery = "UPDATE Users SET user_name = ? WHERE user_id = ?";
        logger.debug("setNewUsernameByUserId - получение preparedStatement по запросу: " + sqlQuery);
        try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery)) {
            preparedStatement.setString(1, newUsername);
            preparedStatement.setInt(2, userId);
            logger.debug("setNewUsernameByUserId - выполнение preparedStatement: " + preparedStatement);
            preparedStatement.executeUpdate();
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    private User getUserByUsername(String username) {
        User result = null;
        for (User user : users) {
            if (user.username.equals(username)) {
                result = user;
                break;
            }
        }
        if (result == null) {
            logger.error("Не найден пользователь по имени: " + username);
            throw new RuntimeException("Не найден пользователь по имени: " + username);
        }
        return result;
    }

    private byte[] getSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    private String getDefaultPasswordForAdmin() {
        // Нужна только для создания первого пользователя admin/admin
        // Чтобы пользователь потом мог войти, так как с клиента летит хешированный (этой же солью) пароль
        byte[] fixedSalt = "My unique fixed salt".getBytes();
        byte[] hash = getHash("admin", fixedSalt);
        return encodeToString(hash);
    }

    private byte[] getHash(String password, byte[] salt) {
        try {
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            return factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private String getHashString(String password, byte[] salt) {
        byte[] hash = getHash(password, salt);
        return encodeToString(hash);
    }

    private String encodeToString(byte[] data) {
        return Base64.getEncoder().withoutPadding().encodeToString(data);
    }

    private byte[] decodeToByteArray(String data) {
        return Base64.getDecoder().decode(data);
    }
}
