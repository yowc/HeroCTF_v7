package com.challenge.drive.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record RemoteUploadDto(
        @NotBlank(message = "URL is required")
        @Size(min = 3, max = 2048, message = "URL must be between 3 and 2048 characters")
        String url,

        @NotNull(message = "Filename is required")
        @NotBlank(message = "Filename is required")
        @Size(min = 1, max = 255, message = "Filename must be between 1 and 255 characters")
        String filename,

        @NotBlank(message = "HTTP method is required")
        @Size(min = 3, max = 255, message = "HTTP method must be between 3 and 255 characters")
        String httpMethod
) {
    public RemoteUploadDto(String url, String filename) {
        this(url, filename, "GET");
    }
}