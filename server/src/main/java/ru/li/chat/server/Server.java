package ru.li.chat.server;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.commons.lang3.StringUtils;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class Server {
    private ServerSocket serverSocket;
    private final int port;
    private final Logger logger;
    private final Map<String, ClientHandler> clients;
    private final UserService userService;
    private boolean running;
    private final String greetings;
    private final String helperStart;
    private final String helperUser;
    private final String helperAdmin;

    public String getHelperStart() {
        return helperStart;
    }

    public Server(int port) {
        this.port = port;
        this.logger = LogManager.getLogger(Server.class.getName());
        this.clients = new HashMap<>();
        this.userService = new InDataBaseUserService();
        this.greetings = getFileContents("server/src/main/resources/greetings.txt");
        this.helperStart = getFileContents("server/src/main/resources/helper_start.txt");
        this.helperUser = getFileContents("server/src/main/resources/helper_user.txt");
        this.helperAdmin = getFileContents("server/src/main/resources/helper_admin.txt");
    }

    public void start() {
        try {
            serverSocket = new ServerSocket(port);
            running = true;
            logger.info(String.format("Запущен сервер на порту: %d", port));
            runTaskToCheckLatestActivity();
            while (running) {
                Socket clientSocket = serverSocket.accept();
                new ClientHandler(clientSocket, this);
            }
        } catch (IOException e) {
            if (!running) {
                return;
            }
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        } finally {
            disconnect();
        }
    }

    private void runTaskToCheckLatestActivity() {
        ScheduledExecutorService executorService = Executors.newSingleThreadScheduledExecutor();
        executorService.scheduleWithFixedDelay(() -> {
            for (ClientHandler clientHandler : clients.values()) {
                if (clientHandler.getLastActivity().plusMinutes(20).isBefore(OffsetDateTime.now())) {
                    logger.info(String.format("%s отключен от чата за не активность.", clientHandler));
                    clientHandler.sendMessage(String.format("%s вы были отключены от чата. Будьте активнее!", serverPrefix()));
                    clientHandler.sendMessage("/exit");
                    clientHandler.disconnect();
                }
            }
        }, 0, 1, TimeUnit.MINUTES);
        logger.info(String.format("Запущен поток на отслеживание активности %s", executorService));
    }

    public synchronized boolean tryToRegister(String message, ClientHandler clientHandler) {
        String[] elements = message.split(" ");
        if (elements.length != 4) {
            logger.warn(String.format("%s Неверный формат команды: %s", clientHandler, message));
            clientHandler.sendMessage(String.format("%s неверный формат команды", serverPrefix()));
            return false;
        }
        String username = elements[1];
        String login = elements[2];
        String password = elements[3];
        if (userService.isUsernameExists(username)) {
            logger.warn(String.format("username уже занят: %s", username));
            clientHandler.sendMessage(String.format("%s username уже занят", serverPrefix()));
            return false;
        }
        if (userService.isLoginAlreadyExists(login)) {
            logger.warn(String.format("login уже занят: %s", login));
            clientHandler.sendMessage(String.format("%s login уже занят", serverPrefix()));
            return false;
        }
        userService.createNewUser(username, login, password, UserRole.USER);
        clientHandler.setUsername(username);
        clientHandler.sendMessage(String.format("%s %s", serverPrefix(), greetings));
        clientHandler.sendMessage(String.format("%s регистрация прошла успешно", serverPrefix()));
        clientHandler.sendMessage(String.format("%s вы подключились к чату под пользователем: %s", serverPrefix(), clientHandler.getUsername()));
        clientHandler.sendMessage(String.format("%s /? - список доступных команд", serverPrefix()));
        subscribe(clientHandler);
        return true;
    }

    public synchronized boolean tryToAuthenticate(String message, ClientHandler clientHandler) {
        String[] elements = message.split(" ");
        if (elements.length != 3) {
            logger.warn(String.format("%s Неверный формат команды: %s", clientHandler, message));
            clientHandler.sendMessage(String.format("%s неверный формат команды", serverPrefix()));
            return false;
        }
        String login = elements[1];
        String password = elements[2];
        String usernameFromUserService = userService.getUsernameByLoginAndPassword(login, password);
        if (usernameFromUserService == null) {
            logger.warn(String.format("%s Неверно указан логин или пароль: %s", clientHandler, message));
            clientHandler.sendMessage(String.format("%s неверно указан логин или пароль", serverPrefix()));
            return false;
        }
        if (isUserBusy(usernameFromUserService)) {
            logger.warn(String.format("%s Пользователь этой учетной записи уже в чате: %s", clientHandler, message));
            clientHandler.sendMessage(String.format("%s пользователь этой учетной записи уже в чате", serverPrefix()));
            return false;
        }
        OffsetDateTime userBanTime = userService.getUserBanTime(usernameFromUserService);
        if (userBanTime == OffsetDateTime.MAX) {
            logger.warn(String.format("%s Попытка входа в заблокированную учетную запись: бан до %s", clientHandler, userBanTime));
            clientHandler.sendMessage(String.format("%s учетная запись заблокирована навсегда", serverPrefix()));
            return false;
        }
        if (userBanTime != null && OffsetDateTime.now().isBefore(userBanTime)) {
            logger.warn(String.format("%s Попытка входа в заблокированную учетную запись: бан до %s", clientHandler, userBanTime));
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss ZZZZ");
            formatter.withZone(ZoneId.systemDefault());
            clientHandler.sendMessage(String.format("%s учетная запись заблокирована до %s", serverPrefix(), userBanTime.format(formatter)));
            return false;
        }
        clientHandler.setUsername(usernameFromUserService);
        clientHandler.sendMessage(String.format("%s %s", serverPrefix(), greetings));
        clientHandler.sendMessage(String.format("%s вы подключились к чату под пользователем: %s", serverPrefix(), clientHandler.getUsername()));
        clientHandler.sendMessage(String.format("%s /? - список доступных команд", serverPrefix()));
        subscribe(clientHandler);
        return true;
    }

    public String getCommandList(ClientHandler clientHandler) {
        String commandList = helperUser;
        if (isUserAdmin(clientHandler.getUsername())) {
            commandList += helperAdmin;
        }
        return commandList;
    }

    public synchronized void sendRolesList(ClientHandler clientHandler) {
        if (commandNotAvailable("при получении списка доступных ролей", clientHandler)) {
            return;
        }
        clientHandler.sendMessage(String.format("%s список доступных ролей: %s", serverPrefix(), Arrays.toString(UserRole.values())));
    }

    public String getActiveUsers() {
        StringBuilder sb = new StringBuilder();
        sb.append("В чате сейчас находятся:\n");
        for (String username : clients.keySet()) {
            sb.append(username).append("\n");
        }
        return sb.toString();
    }

    public void sendPrivateMessage(String message, ClientHandler sender) {
        String[] elements = message.strip().split(" ", 3);
        if (elements.length < 3) {
            logger.warn(String.format("%s Неверный формат команды: %s", sender, message));
            sender.sendMessage(String.format("%s неверный формат команды", serverPrefix()));
            return;
        }
        String receiverUsername = elements[1];
        ClientHandler receiver = clients.get(receiverUsername);
        if (receiver == null) {
            logger.warn(String.format("Не найден пользователь: %s", receiverUsername));
            sender.sendMessage(String.format("%s не найден пользователь: %s", serverPrefix(), receiverUsername));
            return;
        }
        if (sender == receiver) {
            logger.warn(String.format("%s Попытка отправки сообщения самому себе: %s", sender, message));
            sender.sendMessage("Вы пытаетесь отправить сообщение самому себе..");
            return;
        }
        String wispMessage = String.format("%s -> %s: %s", sender.getUsername(), receiver.getUsername(), elements[2]);
        receiver.sendMessage(wispMessage);
        sender.sendMessage(wispMessage);

    }

    public synchronized void sendBroadcastMessage(String message) {
        for (ClientHandler clientHandler : clients.values()) {
            clientHandler.sendMessage(message);
        }
    }

    public synchronized void sendUserInfo(String message, ClientHandler clientHandler) {
        if (commandNotAvailable("при получении списка ролей пользователя", clientHandler)) {
            return;
        }
        String[] elements = message.split(" ");
        if (elements.length != 2) {
            logger.warn(String.format("%s Неверный формат команды: %s", clientHandler, message));
            clientHandler.sendMessage(String.format("%s Неверный формат команды", serverPrefix()));
            return;
        }
        String username = elements[1];
        if (!userService.isUsernameExists(username)) {
            logger.warn(String.format("%s Не найден пользователь: %s", clientHandler, username));
            clientHandler.sendMessage(String.format("%s не найден пользователь: %s", serverPrefix(), clientHandler));
            return;
        }
        String userInfo = userService.getUserInfo(username);
        String lastActivity = "не в сети";
        if (clients.get(username) != null) {
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd hh:mm:ss Z");
            lastActivity = clients.get(username).getLastActivity().format(formatter);
        }
        clientHandler.sendMessage(String.format("%s lastActivity: %s", userInfo, lastActivity));
    }

    private boolean commandNotAvailable(String event, ClientHandler clientHandler) {
        if (!isUserAdmin(clientHandler.getUsername())) {
            logger.warn(String.format("%s превышение полномочий %s", clientHandler, event));
            clientHandler.sendMessage(String.format("%s неизвестная команда", serverPrefix()));
            return true;
        }
        return false;
    }

    public synchronized void changeUsername(String message, ClientHandler clientHandler) {
        String[] elements = message.split(" ");
        if (elements.length != 2) {
            logger.warn(String.format("%s Неверный формат команды: %s", clientHandler, message));
            clientHandler.sendMessage(String.format("%s неверный формат команды", serverPrefix()));
            return;
        }
        String newUsername = elements[1];
        String oldUsername = clientHandler.getUsername();
        if (oldUsername.equals(newUsername)) {
            clientHandler.sendMessage("Этот ник и так уже принадлежит Вам..");
            return;
        }
        if (userService.isUsernameExists(newUsername)) {
            logger.warn(String.format("%s ник %s уже занят", clientHandler, newUsername));
            clientHandler.sendMessage(String.format("%s ник %s уже занят", serverPrefix(), newUsername));
            return;
        }
        if (!userService.changeUsername(oldUsername, newUsername)) {
            logger.error(String.format("%s внутренняя ошибка логики работы приложения. Не найден пользователь: %s", clientHandler, oldUsername));
            clientHandler.sendMessage(String.format("%s внутренняя ошибка логики работы приложения. Обратитесь к администратору", serverPrefix()));
            return;
        }
        logger.info(String.format("%s сменил ник на: %s", clientHandler, newUsername));
        clientHandler.setUsername(newUsername);
        clients.remove(oldUsername);
        clients.put(newUsername, clientHandler);
        sendBroadcastMessage(String.format("%s %s сменил ник на: %s", serverPrefix(), oldUsername, newUsername));
    }

    public synchronized void addRoleToUser(String message, ClientHandler clientHandler) {
        if (commandNotAvailable("при добавлении роли пользователю", clientHandler)) {
            return;
        }
        String[] elements = message.split(" ");
        if (elements.length != 3) {
            logger.warn(String.format("%s неверный формат команды: %s", clientHandler, message));
            clientHandler.sendMessage(String.format("%s неверный формат команды", serverPrefix()));
            return;
        }
        String username = elements[1];
        String roleName = elements[2];
        if (!addRoleIsAvailable(username, roleName, clientHandler)) {
            return;
        }
        userService.addRole(username, roleName);
        logger.info(String.format("%s добавил пользователю %s роль %s", clientHandler, username, roleName));
        clientHandler.sendMessage(String.format("%s пользователю %s добавлена роль %s", serverPrefix(), username, roleName));
        if (clients.containsKey(username) && !clientHandler.getUsername().equals(username)) {
            clients.get(username).sendMessage(String.format("%s пользователь %s добавил вам роль %s", serverPrefix(), clientHandler.getUsername(), roleName));
        }
    }

    public synchronized void removeRoleFromUser(String message, ClientHandler clientHandler) {
        if (commandNotAvailable("при удалении роли у пользователя", clientHandler)) {
            return;
        }
        String[] elements = message.split(" ");
        if (elements.length != 3) {
            logger.warn(String.format("%s неверный формат команды: %s", clientHandler, message));
            clientHandler.sendMessage(String.format("%s неверный формат команды", serverPrefix()));
            return;
        }
        String username = elements[1];
        String roleName = elements[2];
        if (!removeRoleIsAvailable(username, roleName, clientHandler)) {
            return;
        }
        userService.removeRole(username, roleName);
        logger.info(String.format("%s удалил пользователю %s роль %s", clientHandler, username, roleName));
        clientHandler.sendMessage(String.format("%s пользователю %s удалена роль %s", serverPrefix(), username, roleName));
        if (clients.containsKey(username) && !clientHandler.getUsername().equals(username)) {
            clients.get(username).sendMessage(String.format("%s пользователь %s удалил у Вас роль %s", serverPrefix(), clientHandler.getUsername(), roleName));
        }
    }

    private boolean removeRoleIsAvailable(String username, String roleName, ClientHandler clientHandler) {
        if (!userService.isUsernameExists(username)) {
            logger.warn(String.format("%s не найден пользователь %s", clientHandler, username));
            clientHandler.sendMessage(String.format("%s не найден пользователь %s", serverPrefix(), username));
            return false;
        }
        if (roleNotExist(roleName)) {
            logger.warn(String.format("%s не найдена роль %s", clientHandler, roleName));
            clientHandler.sendMessage(String.format("%s не найдена роль %s", serverPrefix(), roleName));
            return false;
        }
        if (!userService.isUserHasRole(username, roleName)) {
            logger.warn(String.format("%s у пользователя %s и так нет роли: %s", clientHandler, username, roleName));
            clientHandler.sendMessage(String.format("%s у пользователя %s и так нет роли: %s", serverPrefix(), username, roleName));
            return false;
        }
        if (userService.isUserHasOneRole(username)) {
            logger.warn(String.format("%s Отказ. После удаления роли %s у пользователя %s не останется ни одной роли", clientHandler, roleName, username));
            clientHandler.sendMessage(String.format("%s Отказ. После удаления роли %s у пользователя %s не останется ни одной роли", serverPrefix(), roleName, username));
            return false;
        }
        if (UserRole.ADMIN.toString().equals(roleName) && userService.isUserLastAdmin(username)) {
            logger.warn(String.format("%s Отказ. После удаления роли %s у пользователя %s в базе не останется ни одного администратора", clientHandler, roleName, username));
            clientHandler.sendMessage(String.format("%s Отказ. После удаления роли %s у пользователя %s в базе не останется ни одного администратора", serverPrefix(), roleName, username));
            return false;
        }
        return true;
    }

    private boolean addRoleIsAvailable(String username, String roleName, ClientHandler clientHandler) {
        if (!userService.isUsernameExists(username)) {
            logger.warn(String.format("%s не найден пользователь %s", clientHandler, username));
            clientHandler.sendMessage(String.format("%s не найден пользователь: %s", serverPrefix(), username));
            return false;
        }
        if (roleNotExist(roleName)) {
            logger.warn(String.format("%s не найдена роль: %s", clientHandler, roleName));
            clientHandler.sendMessage(String.format("%s не найдена роль: %s", serverPrefix(), roleName));
            return false;
        }
        if (userService.isUserHasRole(username, roleName)) {
            logger.warn(String.format("%s у пользователя %s уже есть роль: %s", clientHandler, username, roleName));
            clientHandler.sendMessage(String.format("%s у пользователя %s уже есть роль: %s", serverPrefix(), username, roleName));
            return false;
        }
        return true;
    }

    private static boolean roleNotExist(String roleName) {
        for (UserRole role : UserRole.values()) {
            if (role.toString().equals(roleName)) {
                return false;
            }
        }
        return true;
    }

    public synchronized void banUser(String message, ClientHandler clientHandler) {
        if (commandNotAvailable("при установке бана", clientHandler)) {
            return;
        }
        String[] elements = message.split(" ");
        if (elements.length != 3) {
            logger.warn(String.format("%s неверный формат команды: %s", clientHandler, message));
            clientHandler.sendMessage(String.format("%s неверный формат команды", serverPrefix()));
            return;
        }
        String username = elements[1];
        String banTimeString = elements[2];
        if (!banUserIsAvailable(username, banTimeString, clientHandler)) {
            return;
        }
        OffsetDateTime banTime = getBanTime(banTimeString);
        userService.banUser(username, banTime);
        ClientHandler bannedClientHandler = clients.get(username);
        logger.info(String.format("%s для пользователя %s установил время бана %s", clientHandler, username, banTime));
        String banMessage = getBanMessage(username, banTime, clientHandler);
        sendBroadcastMessage(banMessage);
        if (bannedClientHandler != null && banTime != null) {
            bannedClientHandler.sendMessage("/exit");
            bannedClientHandler.disconnect();
        }
    }

    private String getBanMessage(String username, OffsetDateTime banTime, ClientHandler clientHandler) {
        if (banTime == null) {
            return String.format("%s %s разбанил %s", serverPrefix(), clientHandler.getUsername(), username);
        }
        if (banTime == OffsetDateTime.MAX) {
            return String.format("%s %s забанил %s навсегда", serverPrefix(), clientHandler.getUsername(), username);
        }
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd hh:mm:ss Z");
        return String.format("%s %s забанил %s до %s", serverPrefix(), clientHandler.getUsername(), username, banTime.format(formatter));
    }

    private static OffsetDateTime getBanTime(String banTimeString) {
        if (banTimeString.equals("*")) {
            return OffsetDateTime.MAX;
        }
        if (StringUtils.isNumeric(banTimeString)) {
            return OffsetDateTime.now().plusHours(Integer.parseInt(banTimeString));
        }
        return null;
    }

    private boolean banUserIsAvailable(String username, String banTimeString, ClientHandler clientHandler) {
        if (!userService.isUsernameExists(username)) {
            logger.warn(String.format("%s не найден пользователь %s", clientHandler, username));
            clientHandler.sendMessage(String.format("%s не найден пользователь: %s", serverPrefix(), username));
            return false;
        }
        if (!(StringUtils.isNumeric(banTimeString) || banTimeString.equals("*") || banTimeString.equals("-"))) {
            logger.warn(String.format("%s неверный формат команды бана: %s", clientHandler, banTimeString));
            clientHandler.sendMessage(String.format("%s неверный формат команды", serverPrefix()));
            return false;
        }
        if (clientHandler.getUsername().equals(username)) {
            logger.warn(String.format("%s Отказ. Попытка забанить самого себя", clientHandler));
            clientHandler.sendMessage(String.format("%s Отказ. Пытаетесь забанить самого себя..", serverPrefix()));
            return false;
        }
        OffsetDateTime userBanTime = userService.getUserBanTime(username);
        if (banTimeString.equals("-") && userBanTime == null) {
            logger.warn(String.format("%s Отказ. Попытка разбанить не заблокированного пользователя %s", clientHandler, username));
            clientHandler.sendMessage(String.format("%s пользователь %s и так не заблокирован", serverPrefix(), username));
            return false;
        }
        return true;
    }

    public boolean isUserAdmin(String username) {
        return userService.isUserAdmin(username);
    }

    private boolean isUserBusy(String username) {
        return clients.containsKey(username);
    }

    public String serverPrefix() {
        return "[СЕРВЕР]";
    }

    public synchronized void unsubscribe(ClientHandler clientHandler) {
        clients.remove(clientHandler.getUsername());
        if (clientHandler.getUsername() != null) {
            logger.info(String.format("%s отключился от чата", clientHandler));
            sendBroadcastMessage(String.format("%s Отключился пользователь: %s", serverPrefix(), clientHandler.getUsername()));
        }
    }

    private synchronized void subscribe(ClientHandler clientHandler) {
        logger.info(String.format("%s подключился к чату", clientHandler));
        sendBroadcastMessage(String.format("%s Подключился пользователь: %s", serverPrefix(), clientHandler.getUsername()));
        clients.put(clientHandler.getUsername(), clientHandler);
    }

    public synchronized void shutdown(ClientHandler clientHandler) {
        if (commandNotAvailable("при выключении сервера", clientHandler)) {
            return;
        }
        running = false;
        sendBroadcastMessage(String.format("%s Сервер был остановлен", serverPrefix()));
        sendBroadcastMessage("/exit");
        disconnect();
    }

    private synchronized void disconnect() {
        for (ClientHandler clientHandler : clients.values()) {
            clientHandler.disconnect();
        }
        logger.info("Сервер остановлен");
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException e) {
            logger.warn(e.getMessage());
        }
    }

    private String getFileContents(String filePath) {
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
            return sb.toString();
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
        return "";
    }
}
