package ru.li.chat.server;

public class ServerApplication {
    public static void main(String[] args) {
        Server server = new Server(Integer.parseInt(String.valueOf(System.getProperties().getOrDefault("port", 8089))));
        server.start();
    }
}
