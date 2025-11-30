package com.challenge.drive.config;

import com.challenge.drive.model.UserModel;
import com.challenge.drive.repository.UserRepository;
import com.challenge.drive.util.CryptoUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DataInitializer {

    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);

    @Bean
    CommandLineRunner initDatabase(UserRepository userRepository) {
        return args -> {
            if (userRepository.findByUsername("admin") == null) {
                UserModel adminUser = new UserModel();
                // adminUser.setId(1);
                adminUser.setUsername("admin");
                adminUser.setEmail("admin@example.com");
                adminUser.setPassword(CryptoUtils.generateRandomHex());
                userRepository.save(adminUser);
                logger.info("Admin user created!");
            } else {
                logger.info("Admin user already created!");
            }
        };
    }
}
