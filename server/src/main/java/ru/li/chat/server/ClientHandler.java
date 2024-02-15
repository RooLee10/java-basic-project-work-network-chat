package ru.li.chat.server;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.time.OffsetDateTime;

public class ClientHandler {
    private String username;
    private final Server server;
    private final Socket socket;
    private final DataInputStream in;
    private final DataOutputStream out;
    private final Logger logger;
    private OffsetDateTime lastActivity;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public OffsetDateTime getLastActivity() {
        return lastActivity;
    }

    public ClientHandler(Socket socket, Server server) throws IOException {
        this.logger = LogManager.getLogger(ClientHandler.class.getName());
        this.socket = socket;
        this.in = new DataInputStream(socket.getInputStream());
        this.out = new DataOutputStream(socket.getOutputStream());
        this.server = server;
        this.lastActivity = OffsetDateTime.now();

        new Thread(() -> {
            try {
                startLogic();
                mainLogic();
            } catch (IOException e) {
                logger.error(e.getMessage());
            } finally {
                disconnect();
                server.unsubscribe(this);
            }
        }).start();

        logger.info(String.format("Подключился клиент: %s:%d", socket.getInetAddress(), socket.getPort()));
    }

    @Override
    public String toString() {
        return String.format("Клиент %s:%s (%s)", socket.getInetAddress(), socket.getPort(), username);
    }

    private void startLogic() throws IOException {
        sendMessage(String.format("%s %s", serverPrefix(), server.getHelperStart()));
        while (true) {
            String message = in.readUTF();
            setLastActivity();
            logger.info(this + " -> " + message);
            boolean successfully = false;
            if (message.startsWith("/register ")) {
                successfully = server.tryToRegister(message, this);
            } else if (message.startsWith("/auth ")) {
                successfully = server.tryToAuthenticate(message, this);
            } else if (message.equals("/exit")) {
                sendMessage("/disconnect");
                disconnect();
            } else {
                logger.warn(String.format("Неизвестная команда: %s", message));
                sendMessage(String.format("%s неизвестная команда", serverPrefix()));
            }
            if (successfully) {
                break;
            }
        }
    }

    private void mainLogic() throws IOException {
        while (true) {
            String message = in.readUTF();
            setLastActivity();
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
                if (message.startsWith("/userinfo ")) {
                    server.sendUserInfo(message, this);
                    continue;
                }
                if (message.equals("/roleslist")) {
                    server.sendRolesList(this);
                    continue;
                }
                if (message.startsWith("/addrole ")) {
                    server.addRoleToUser(message, this);
                    continue;
                }
                if (message.startsWith("/removerole ")) {
                    server.removeRoleFromUser(message, this);
                    continue;
                }
                if (message.startsWith("/ban ")) {
                    server.banUser(message, this);
                    continue;
                }
                if (message.equals("/exit")) {
                    sendMessage(message);
                    disconnect();
                    break;
                }
                if (message.equals("/shutdown")) {
                    server.shutdown(this);
                    continue;
                }
                sendMessage(String.format("%s неизвестная команда", serverPrefix()));
            } else {
                server.sendBroadcastMessage(String.format("%s : %s", username, message));
            }
        }
    }

    public void sendMessage(String message) {
        try {
            out.writeUTF(message);
        } catch (IOException e) {
            logger.warn(e.getMessage());
        }
    }

    private void setLastActivity() {
        this.lastActivity = OffsetDateTime.now();
    }

    private String serverPrefix() {
        return server.serverPrefix();
    }

    public void disconnect() {
        logger.info(String.format("Отключился клиент: %s:%s", socket.getInetAddress(), socket.getPort()));
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
