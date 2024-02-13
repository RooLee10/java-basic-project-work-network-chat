package ru.li.chat.client;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Scanner;

public class ClientApplication {
    private static LocalDateTime localDateTime = LocalDateTime.now(); // Время клиента, так как сервер может быть в другом часовом поясе
    private static DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        try (Network network = new Network()) {
            network.setOnMessageReceived(System.out::println);
            network.connect(Integer.parseInt(String.valueOf(System.getProperties().getOrDefault("port", 8089))));
            while (true) {
                String message = scanner.nextLine();
                message = message.trim();
                if (!network.isConnected()) {
                    network.getOnMessageReceived().callback(getLocalDataString() + " [СЕРВЕР] Вы не подключены к чату");
                    break;
                }
                if (message.isEmpty()) {
                    continue;
                }
                if (message.startsWith("/register ")) {
                    String[] elements = message.split(" ");
                    if (elements.length != 4) {
                        network.getOnMessageReceived().callback(getLocalDataString() + " [СЕРВЕР] неверный формат команды");
                        continue;
                    }
                    elements[3] = changePasswordToHashWithFixedSalt(elements[3]);
                    message = String.join(" ", elements);
                }
                if (message.startsWith("/auth ")) {
                    String[] elements = message.split(" ");
                    if (elements.length != 3) {
                        network.getOnMessageReceived().callback(getLocalDataString() + " [СЕРВЕР] неверный формат команды");
                        continue;
                    }
                    elements[2] = changePasswordToHashWithFixedSalt(elements[2]);
                    message = String.join(" ", elements);
                }
                network.send(message);
                if (message.equals("/exit")) {
                    break;
                }
            }
            while (network.isConnected()) {
                // Ожидаем получения "/exit" в другом потоке и завершаем программу
                Thread.sleep(100);
            }
        } catch (IOException | InterruptedException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private static String getLocalDataString() {
        return "[" + localDateTime.format(formatter) + "]";
    }

    private static String changePasswordToHashWithFixedSalt(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Хоть какая-то защита от передачи пароля по сети в открытом виде
        byte[] fixedSalt = "My unique fixed salt".getBytes();
        byte[] hash = getHash(password, fixedSalt);
        return Base64.getEncoder().withoutPadding().encodeToString(hash);
    }

    private static byte[] getHash(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        return factory.generateSecret(spec).getEncoded();
    }
}
