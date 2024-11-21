package com.example.userservice.dtos;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LogoutResponseDto {
    private String message;
}
