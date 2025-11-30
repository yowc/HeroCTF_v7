package com.challenge.drive.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record SendResetPasswordDto(
        @NotBlank(message = "Email is required")
        @Size(min = 3, max = 64, message = "Email must be between 3 and 64 characters")
        String email
) {
}