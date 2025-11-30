package com.challenge.drive.util;

import com.challenge.drive.model.UserModel;

import java.util.ArrayList;
import java.util.UUID;

public class ResetPasswordStorage {

    private static ResetPasswordStorage instance;
    private final ArrayList<ResetPasswordToken> resetPasswordTokens;

    private ResetPasswordStorage() {
        this.resetPasswordTokens = new ArrayList<>();
    }

    public static synchronized ResetPasswordStorage getInstance() {
        if (instance == null) {
            instance = new ResetPasswordStorage();
        }
        return instance;
    }

    private String createUniqueToken(UserModel user) {
        return UUID.randomUUID() + "|" + user.getId();
    }

    public ResetPasswordToken createResetPasswordToken(UserModel user) {
        ResetPasswordToken resetPasswordToken = new ResetPasswordToken(createUniqueToken(user), user.getEmail());
        resetPasswordTokens.add(resetPasswordToken);
        return resetPasswordToken;
    }

    public int getUserFromResetPasswordToken(String email, String uniqueToken) {
        ResetPasswordToken resetPasswordToken = new ResetPasswordToken(uniqueToken, email);
        if (resetPasswordTokens.contains(resetPasswordToken)) {
            return Integer.parseInt(uniqueToken.split("\\|")[1]);
        }
        return -1;
    }

}
