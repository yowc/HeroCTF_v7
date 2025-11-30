package com.challenge.drive.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import redis.clients.jedis.Jedis;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

@Service
public class ClamAVService {

    private static final Logger logger = LoggerFactory.getLogger(ClamAVService.class);

    private static final String QUEUE_KEY = "clamav_queue";

    private static volatile ClamAVService instance;
    private final Jedis jedis;

    public ClamAVService() {
        this.jedis = new Jedis("localhost", 6379);
    }

    public static ClamAVService getInstance() {
        if (instance == null) {
            synchronized (ClamAVService.class) {
                if (instance == null) {
                    instance = new ClamAVService();
                }
            }
        }
        return instance;
    }

    public void addToScan(String filePath) {
        jedis.rpush(QUEUE_KEY, filePath);
    }

    public String dequeue() {
        return jedis.lpop(QUEUE_KEY);
    }

    public boolean isEmpty() {
        return jedis.llen(QUEUE_KEY) == 0;
    }

    @Scheduled(fixedRate = 60 * 1000)
    public void scanAllFiles() {
        logger.info("Scanning all files...");
        while (!this.isEmpty()) {
            String filePath = this.dequeue();
            logger.info("Scanning file {}...", filePath);
            if (!this.isFileClean(filePath)) {
                try {
                    Files.deleteIfExists(Paths.get(filePath));
                } catch (IOException ignored) {
                    logger.error("Unable to delete the file {}", filePath);
                }
            }
        }
    }

    public boolean isFileClean(String filePath) {
        String command = String.format("clamscan --quiet '%s'", filePath);
        ProcessBuilder processBuilder = new ProcessBuilder("/bin/sh", "-c", command);

        try {
            Process process = processBuilder.start();
            return process.waitFor() == 0;
        } catch (Exception ignored) {
            logger.error("Unable to scan the file {}", filePath);
        }
        return false;
    }

}
