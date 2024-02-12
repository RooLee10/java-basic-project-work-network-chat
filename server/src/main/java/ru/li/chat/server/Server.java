package ru.li.chat.server;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

public class Server {
    private ServerSocket serverSocket;
    private final int port;
    private final Logger logger;
    private Map<String, ClientHandler> clients;
    private UserService userService;
    private boolean running;
    private String greetings;
    private String helperStart;
    private String helperUser;
    private String helperAdmin;

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
            logger.info("Запущен сервер на порту: " + port);
            while (running) {
                Socket clientSocket = serverSocket.accept();
                logger.info("Подключился клиент: " + clientSocket.getInetAddress() + ":" + clientSocket.getPort());
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

    public synchronized boolean tryToRegister(String message, ClientHandler clientHandler) {
        String[] elements = message.split(" ");
        if (elements.length != 4) {
            logger.warn("Неверный формат команды: " + message);
            clientHandler.sendMessage("[СЕРВЕР] неверный формат команды");
            return false;
        }
        String username = elements[1];
        String login = elements[2];
        String password = elements[3];
        if (userService.isUsernameAlreadyExists(username)) {
            logger.warn("username уже занят: " + username);
            clientHandler.sendMessage("[СЕРВЕР] username уже занят");
            return false;
        }
        if (userService.isLoginAlreadyExists(login)) {
            logger.warn("login уже занят: " + login);
            clientHandler.sendMessage("[СЕРВЕР] login уже занят");
            return false;
        }
        userService.createNewUser(username, login, password, UserRole.USER);
        clientHandler.setUsername(username);
        clientHandler.sendMessage("[СЕРВЕР] " + greetings);
        clientHandler.sendMessage("[СЕРВЕР] регистрация прошла успешно");
        clientHandler.sendMessage("[СЕРВЕР] вы подключились к чату под пользователем: " + clientHandler.getUsername());
        clientHandler.sendMessage("[СЕРВЕР] /? - список доступных команд");
        subscribe(clientHandler);
        return true;
    }

    public synchronized boolean tryToAuthenticate(String message, ClientHandler clientHandler) {
        String[] elements = message.split(" ");
        if (elements.length != 3) {
            logger.warn("Неверный формат команды: " + message);
            clientHandler.sendMessage("[СЕРВЕР] неверный формат команды");
            return false;
        }
        String login = elements[1];
        String password = elements[2];
        String usernameFromUserService = userService.getUsernameByLoginAndPassword(login, password);
        if (usernameFromUserService == null) {
            logger.warn("Неверно указан логин или пароль: " + message);
            clientHandler.sendMessage("[СЕРВЕР] неверно указан логин или пароль");
            return false;
        }
        if (isUserBusy(usernameFromUserService)) {
            logger.warn("Пользователь этой учетной записи уже в чате: " + message);
            clientHandler.sendMessage("[СЕРВЕР] пользователь этой учетной записи уже в чате");
            return false;
        }
        clientHandler.setUsername(usernameFromUserService);
        clientHandler.sendMessage("[СЕРВЕР] " + greetings);
        clientHandler.sendMessage("[СЕРВЕР] вы подключились к чату под пользователем: " + clientHandler.getUsername());
        clientHandler.sendMessage("[СЕРВЕР] /? - список доступных команд");
        subscribe(clientHandler);
        return true;
    }

    public String getCommandList(ClientHandler clientHandler) {
        String commandList = helperUser;
        if (userService.isUserAdmin(clientHandler.getUsername())) {
            commandList += helperAdmin;
        }
        return commandList;
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
            logger.warn("Неверный формат команды: " + message);
            sender.sendMessage("[СЕРВЕР] неверный формат команды");
            return;
        }
        String receiverUsername = elements[1];
        ClientHandler receiver = null;
        for (String username : clients.keySet()) {
            if (username.equals(receiverUsername)) {
                receiver = clients.get(username);
                break;
            }
        }
        if (receiver == null) {
            logger.warn("Не найден пользователь: " + receiverUsername);
            sender.sendMessage("[СЕРВЕР] не найден пользователь: " + receiverUsername);
            return;
        }
        String wispMessage = sender.getUsername() + "->" + receiver.getUsername() + ": " + elements[2];
        receiver.sendMessage(wispMessage);
        sender.sendMessage(wispMessage);

    }

    public synchronized void changeUsername(String message, ClientHandler clientHandler) {
        String[] elements = message.split(" ");
        if (elements.length != 2) {
            logger.warn("Неверный формат команды: " + message);
            clientHandler.sendMessage("[СЕРВЕР] неверный формат команды");
            return;
        }
        String newUsername = elements[1];
        if (clientHandler.getUsername().equals(newUsername)) {
            clientHandler.sendMessage("Этот ник и так уже принадлежит Вам..");
            return;
        }
        if (!userService.changeUsername(clientHandler.getUsername(), newUsername)) {
            logger.error(clientHandler + " внутренняя ошибка логики работы приложения. Не найден пользователь: " + clientHandler.getUsername());
            clientHandler.sendMessage("[СЕРВЕР] внутренняя ошибка логики работы приложения. Не найден пользователь: " + clientHandler.getUsername());
            return;
        }
        logger.info(clientHandler.getUsername() + " сменил ник на: " + newUsername);
        sendBroadcastMessage("[СЕРВЕР] " + clientHandler.getUsername() + " сменил ник на: " + newUsername);
        clientHandler.setUsername(newUsername);
        clientHandler.sendMessage("[СЕРВЕР] вы сменили ник на: " + clientHandler.getUsername());
    }

    public boolean isUserAdmin(String username) {
        return userService.isUserAdmin(username);
    }
    private boolean isUserBusy(String username) {
        return clients.containsKey(username);
    }

    public synchronized void sendBroadcastMessage(String message) {
        for (ClientHandler clientHandler : clients.values()) {
            clientHandler.sendMessage(message);
        }
    }

    public synchronized void unsubscribe(ClientHandler clientHandler) {
        clients.remove(clientHandler.getUsername());
        logger.info(clientHandler + " отключился от чата");
        sendBroadcastMessage("[СЕРВЕР] Отключился пользователь: " + clientHandler.getUsername());
    }

    private synchronized void subscribe(ClientHandler clientHandler) {
        logger.info(clientHandler + " подключился к чату");
        sendBroadcastMessage("[СЕРВЕР] Подключился пользователь: " + clientHandler.getUsername());
        clients.put(clientHandler.getUsername(), clientHandler);
    }

    public synchronized void shutdown() {
        running = false;
        for (ClientHandler clientHandler : clients.values()) {
            clientHandler.sendMessage("[СЕРВЕР] Сервер был остановлен");
            clientHandler.sendMessage("/exit");
            clientHandler.disconnect();
        }
        disconnect();
    }

    private synchronized void disconnect() {
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
                sb.append(line + "\n");
            }
            return sb.toString();
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
        return "";
    }
}
