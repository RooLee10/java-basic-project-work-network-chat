package ru.li.chat.server;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

public class ClientHandler {
    private Server server;
    private Socket socket;
    private DataInputStream in;
    private DataOutputStream out;
    private String username;
    private final Logger logger;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public ClientHandler(Socket socket, Server server) {
        this.logger = LogManager.getLogger(ClientHandler.class.getName());

        new Thread(() -> {
            try {
                this.socket = socket;
                this.in = new DataInputStream(socket.getInputStream());
                this.out = new DataOutputStream(socket.getOutputStream());
                this.server = server;
                startLogic();
                mainLogic();
            } catch (IOException e) {
                logger.error(e.getMessage());
            } finally {
                disconnect();
                server.unsubscribe(this);
            }
        }).start();
    }

    @Override
    public String toString() {
        return "Клиент " + socket.getInetAddress() + ":" + socket.getPort() + " (" + username + ")";
    }

    private void startLogic() throws IOException {
        sendMessage("[СЕРВЕР] " + server.getHelperStart());
        while (true) {
            String message = in.readUTF();
            logger.info(this + " -> " + message);
            boolean successfully = false;
            if (message.startsWith("/register ")) {
                successfully = server.tryToRegister(message, this);
            } else if (message.startsWith("/auth ")) {
                successfully = server.tryToAuthenticate(message, this);
            } else {
                logger.warn("Неизвестная команда: " + message);
                sendMessage("[СЕРВЕР] неизвестная команда");
            }
            if (successfully) {
                break;
            }
        }
    }

    private void mainLogic() throws IOException {
        while (true) {
            String message = in.readUTF();
            if (message.startsWith("/")) {
                logger.info(this + " -> " + message);
                if (message.equals("/?")) {
                    sendMessage(server.getCommandList(this));
                    continue;
                }
                if (message.equals("/activelist")) {
                    sendMessage(server.getActiveUsers());
                    continue;
                }
                if (message.startsWith("/w ")) {
                    server.sendPrivateMessage(message, this);
                    continue;
                }
                if (message.startsWith("/changenick ")) {
                    server.changeUsername(message, this);
                    continue;
                }
                if (message.equals("/exit")) {
                    sendMessage(message);
                    break;
                }
                if (message.equals("/shutdown")) {
                    if (!server.isUserAdmin(username)) {
                        logger.warn(this + " превышение полномочий");
                        sendMessage("[СЕРВЕР] неизвестная команда");
                        continue;
                    }
                    server.shutdown();
                    break;
                }
            }
            server.sendBroadcastMessage(username + ": " + message);
        }
    }

    public void sendMessage(String message) {
        try {
            out.writeUTF(message);
        } catch (IOException e) {
            logger.warn(e.getMessage());
        }
    }

    public void disconnect() {
        try {
            if (in != null) {
                in.close();
            }
        } catch (IOException e) {
            logger.warn(e.getMessage());
        }
        try {
            if (out != null) {
                out.close();
            }
        } catch (IOException e) {
            logger.warn(e.getMessage());
        }
        try {
            if (socket != null) {
                socket.close();
            }
        } catch (IOException e) {
            logger.warn(e.getMessage());
        }
    }
}
