package ru.li.chat.server;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerApplication {
    private static final Logger LOGGER = LogManager.getLogger(ServerApplication.class.getName());
    public static void main(String[] args) {
        LOGGER.info("Запуск приложения");
        Server server = new Server(Integer.parseInt(String.valueOf(System.getProperties().getOrDefault("port", 8089))));
        server.start();
    }
}
