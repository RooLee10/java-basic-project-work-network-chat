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

    public String getGreetings() {
        return greetings;
    }

    public String getHelperStart() {
        return helperStart;
    }

    public String getHelperUser() {
        return helperUser;
    }

    public String getHelperAdmin() {
        return helperAdmin;
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

    public synchronized boolean tryToRegister(ClientHandler clientHandler) {

        return false;
    }

    public synchronized boolean tryToAuthenticate(ClientHandler clientHandler) {

        return false;
    }

    public synchronized void sendBroadcastMessage(String message) {
        for (ClientHandler clientHandler : clients.values()) {
            clientHandler.sendMessage(message);
        }
    }

    public synchronized void unsubscribe(ClientHandler clientHandler) {
        clients.remove(clientHandler.getUsername());
        logger.info("Отключился пользователь");
        sendBroadcastMessage("[СЕРВЕР] Отключился пользователь");
    }

    private synchronized void subscribe(ClientHandler clientHandler) {
        logger.info("Подключился пользователь");
        sendBroadcastMessage("[СЕРВЕР] Подключился пользователь");
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
