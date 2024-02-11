package ru.li.chat.client;

import java.io.IOException;
import java.util.Scanner;

public class ClientApplication {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        try (Network network = new Network()) {
            network.setOnMessageReceived(System.out::println);
            network.connect(Integer.parseInt(String.valueOf(System.getProperties().getOrDefault("port", 8089))));
            while (true) {
                String message = scanner.nextLine();
                if (!network.isConnected()) {
                    network.getOnMessageReceived().callback("[СЕРВЕР] Вы не подключены к чату");
                    break;
                }
                network.send(message);
                if (message.equals("/exit")) {
                    break;
                }
            }
            // Ожидаем получения "/exit" в другом потоке и завершаем программу
            while (network.isConnected()) {
                Thread.sleep(100);
            }
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
