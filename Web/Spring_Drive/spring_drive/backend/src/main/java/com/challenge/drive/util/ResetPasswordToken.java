package com.challenge.drive.util;

public class ResetPasswordToken {

    private String token;
    private String email;

    public ResetPasswordToken(String token, String email) {
        this.token = token;
        this.email = email;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    @Override
    public String toString() {
        return "ResetPasswordToken [token=" + token + ", email=" + email + "]";
    }

    @Override
    public boolean equals(Object o) {
        return this.token.split("\\|")[0].equals(((ResetPasswordToken) o).token.split("\\|")[0]) && this.hashCode() == o.hashCode();
    }

    @Override
    public int hashCode() {
        return token.hashCode() + email.hashCode();
    }
}
