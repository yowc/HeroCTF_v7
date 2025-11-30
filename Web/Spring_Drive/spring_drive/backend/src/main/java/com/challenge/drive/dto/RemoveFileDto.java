package com.challenge.drive.dto;

import org.hibernate.validator.constraints.Range;

public record RemoveFileDto(
        @Range(min = 1)
        int fileId
) {
}
