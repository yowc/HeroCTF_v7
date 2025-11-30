package com.challenge.drive.util;

import java.security.SecureRandom;

public class CryptoUtils {

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final String HEX_CHARACTERS = "0123456789abcdef";

    public static String generateRandomHex() {
        StringBuilder sb = new StringBuilder(32);
        for (int i = 0; i < 32; i++) {
            int index = secureRandom.nextInt(HEX_CHARACTERS.length());
            sb.append(HEX_CHARACTERS.charAt(index));
        }
        return sb.toString();
    }
}
