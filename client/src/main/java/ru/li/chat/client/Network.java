package ru.li.chat.client;

import java.io.*;
import java.net.Socket;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Network implements AutoCloseable {
    private Socket socket;
    private DataInputStream in;
    private DataOutputStream out;
    private Callback onMessageReceived;
    private boolean connected;

    public void setOnMessageReceived(Callback onMessageReceived) {
        this.onMessageReceived = onMessageReceived;
    }

    public Callback getOnMessageReceived() {
        return onMessageReceived;
    }

    public boolean isConnected() {
        return connected;
    }

    public void connect(int port) throws IOException {
        socket = new Socket("localhost", port);
        this.connected = true;
        System.out.println("Подключились к серверу");
        in = new DataInputStream(socket.getInputStream());
        out = new DataOutputStream(socket.getOutputStream());

        new Thread(() -> {
            try {
                while (true) {
                    String message = in.readUTF();
                    if (message.equals("/disconnect")) {
                        onMessageReceived.callback("Отключились от сервера");
                        this.connected = false;
                        break;
                    }
                    if (message.equals("/exit")) {
                        onMessageReceived.callback("Вы покинули чат");
                        this.connected = false;
                        break;
                    }
                    LocalDateTime localDateTime = LocalDateTime.now(); // Время клиента, так как сервер может быть в другом часовом поясе
                    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
                    onMessageReceived.callback(String.format("[%s] %s", localDateTime.format(formatter), message));
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }).start();
    }

    public void send(String message) throws IOException {
        out.writeUTF(message);
    }

    @Override
    public void close() {
        try {
            if (out != null) {
                out.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            if (in != null) {
                in.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            if (socket != null) {
                socket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
