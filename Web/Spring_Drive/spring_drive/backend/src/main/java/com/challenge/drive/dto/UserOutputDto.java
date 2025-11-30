package com.challenge.drive.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UserOutputDto(
        int id,
        String username,
        String email
) {
        public UserOutputDto(int id, String username, String email) {
                this.id = id;
                this.username = username;
                this.email = email;
        }
}