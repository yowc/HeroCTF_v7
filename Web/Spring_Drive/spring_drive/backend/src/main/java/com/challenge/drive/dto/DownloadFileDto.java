package com.challenge.drive.dto;

import org.hibernate.validator.constraints.Range;

public record DownloadFileDto(
        @Range(min = 1)
        int fileId
) {
}
