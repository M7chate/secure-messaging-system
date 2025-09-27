package mz.ujc.secure_messaging_system;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.web.socket.config.annotation.EnableWebSocket;

@SpringBootApplication
@EnableWebSocket
@EnableAsync
@ComponentScan(basePackages = "mz.ujc.secure_messaging_system") // Ajuste para seu pacote
public class SecureMessagingSystemApplication {
    public static void main(String[] args) {
        SpringApplication.run(SecureMessagingSystemApplication.class, args);
    }
}

