package ru.li.chat.server;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.*;
import java.util.*;

public class InDataBaseUserService implements UserService {
    class User {
        private String username;
        private String login;
        private String password;
        private Set<UserRole> roles;

        public User(String username, String login, String password, Set<UserRole> roles) {
            this.username = username;
            this.login = login;
            this.password = password;
            this.roles = roles;
        }

        @Override
        public String toString() {
            return "User{" +
                    ", username='" + username + '\'' +
                    ", login='" + login + '\'' +
                    ", password='" + password + '\'' +
                    ", roles=" + roles +
                    '}';
        }

        public synchronized void addRole(UserRole role) {
            roles.add(role);
        }

        public synchronized void removeRole(UserRole role) {
            roles.remove(role);
        }
    }

    private static final String DATABASE_URL = "jdbc:postgresql//localhost:5432/homework_26";
    private static final String LOGIN = "postgres";
    private static final String PASSWORD = "123456";
    private List<User> users;
    private final Logger logger = LogManager.getLogger(InDataBaseUserService.class.getName());

    public InDataBaseUserService() {
        this.users = new ArrayList<>();
        fillUsers();
    }

    private void fillUsers() {
        logger.debug("getUsersFromDatabase - подключение к базе данных");
        try (Connection connection = DriverManager.getConnection(DATABASE_URL, LOGIN, PASSWORD)) {
            getUsersFromDatabase(connection);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private void getUsersFromDatabase(Connection connection) throws SQLException {
        String sqlQuery = "SELECT u.user_id, u.user_name, u.login, u.password, r.role_name FROM UserToRole utr JOIN Users u ON utr.user_id = u.user_id JOIN Roles r ON utr.role_id = r.role_id";
        logger.debug("getUsersFromDatabase - получение соединение");
        try (Statement statement = connection.createStatement()) {
            logger.debug("getUsersFromDatabase - получение результата запроса: " + sqlQuery);
            try (ResultSet resultSet = statement.executeQuery(sqlQuery)) {
                Map<Integer, Map<String, String>> idToUsersData = new HashMap<>(); // Для сохранения данных о пользователях
                Map<Integer, Set<UserRole>> idToRole = new HashMap<>(); // Для сохранения ролей пользователей
                while (resultSet.next()) {
                    int userId = resultSet.getInt(1);
                    String userName = resultSet.getString(2);
                    String login = resultSet.getString(3);
                    String password = resultSet.getString(4);
                    String roleName = resultSet.getString(5);
                    // Данные о пользователях
                    if (!idToUsersData.containsKey(userId)) {
                        Map<String, String> userData = new HashMap<>();
                        userData.put("userName", userName);
                        userData.put("login", login);
                        userData.put("password", password);
                        idToUsersData.put(userId, userData);
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
                // Обходим сохраненные данные и создаем пользователей
                for (int userId : idToUsersData.keySet()) {
                    Map<String, String> userData = idToUsersData.get(userId);
                    User user = new User(userData.get("userName"), userData.get("login"), userData.get("password"), idToRole.getOrDefault(userId, new HashSet<>()));
                    this.users.add(user);
                    logger.debug("getUsersFromDatabase - создался пользователь: " + user);
                }
            } catch (SQLException e) {
                logger.error(e.getMessage());
                throw new SQLException(e);
            }
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    @Override
    public String getUsernameByLoginAndPassword(String login, String password) {
        return null;
    }

    @Override
    public boolean isUsernameAlreadyExists(String username) {
        return false;
    }

    @Override
    public boolean isLoginAlreadyExists(String login) {
        return false;
    }

    @Override
    public boolean isUserAdmin(String username) {
        return false;
    }

    @Override
    public void createNewUser(String username, String login, String password, UserRole role) {
        logger.debug("createNewUser - подключение к базе данных");
        try (Connection connection = DriverManager.getConnection(DATABASE_URL, LOGIN, PASSWORD)) {
            connection.setAutoCommit(false);
            insertIntoUsers(username, login, password, connection);
            insertIntoUserToRole(login, role, connection);
            connection.setAutoCommit(true);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
        this.users.add(new User(username, login, password, new HashSet<>(List.of(role))));
    }

    private void insertIntoUserToRole(String login, UserRole role, Connection connection) throws SQLException {
        int userId = getUserIdByLogin(login, connection);
        int roleId = getRoleIdByRoleName(role.toString(), connection);
        String sqlQuery = "INSERT INTO UserToRole (user_id, role_id) values (?, ?)";
        logger.debug("createNewUser - получение preparedStatement по запросу: " + sqlQuery);
        try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery)) {
            preparedStatement.setInt(1, userId);
            preparedStatement.setInt(2, roleId);
            logger.debug("createNewUser - выполнение preparedStatement: " + preparedStatement);
            preparedStatement.executeUpdate();
        } catch (SQLException | RuntimeException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    private void insertIntoUsers(String username, String login, String password, Connection connection) throws SQLException {
        String sqlQuery = "INSERT INTO Users (user_name, login, password) values (?, ?, ?)";
        logger.debug("createNewUser - получение preparedStatement по запросу: " + sqlQuery);
        try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery)) {
            preparedStatement.setString(1, username);
            preparedStatement.setString(2, login);
            preparedStatement.setString(3, password);
            logger.debug("createNewUser - выполнение preparedStatement: " + preparedStatement);
            preparedStatement.executeUpdate();
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    private int getRoleIdByRoleName(String roleName, Connection connection) throws SQLException {
        String sqlQuery = "SELECT r.role_id FROM Roles r WHERE r.role_name = ?";
        logger.debug("getRoleIdByRolename - получение preparedStatement по запросу: " + sqlQuery);
        try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery)) {
            preparedStatement.setString(1, roleName);
            return executeQueryForGetRoleIdByRoleName(connection, roleName, preparedStatement);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    private int executeQueryForGetRoleIdByRoleName(Connection connection, String roleName, PreparedStatement preparedStatement) throws SQLException {
        logger.debug("getRoleIdByRolename - выполнение preparedStatement: " + preparedStatement);
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
        String sqlQuery = "INSERT INTO Roles r (r.role_name) values (?)";
        logger.debug("createNewRole - получение preparedStatement по запросу: " + sqlQuery);
        try (PreparedStatement preparedStatement = connection.prepareStatement(sqlQuery)) {
            preparedStatement.setString(1, roleName);
            logger.debug("createNewRole - выполнение preparedStatement: " + preparedStatement);
            preparedStatement.executeQuery();
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
        logger.debug("getUserIdByLogin - выполнение preparedStatement: " + preparedStatement);
        try (ResultSet resultSet = preparedStatement.executeQuery()) {
            resultSet.next();
            return resultSet.getInt(1);
        } catch (SQLException e) {
            logger.error(e.getMessage());
            throw new SQLException(e);
        }
    }

    @Override
    public void addRoleToUser(String username, UserRole role) {

    }

    @Override
    public void removeRoleFromUser(String username, UserRole role) {

    }
}
