package com.challenge.drive.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterDto(
        @NotBlank(message = "Username is required")
        @Size(min = 3, max = 32, message = "Username must be between 3 and 32 characters")
        String username,

        @NotBlank(message = "Email is required")
        @Size(min = 3, max = 64, message = "Email must be between 3 and 64 characters")
        String email,

        @NotBlank(message = "Password is required")
        @Size(min = 8, message = "Password must be at least 8 characters")
        String password,

        @NotBlank(message = "Confirmation password is required")
        @Size(min = 8, message = "Password must be at least 8 characters")
        String confirmPassword
) {
}