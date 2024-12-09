package com.example.userservice.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class JwtErrorResponseDto {
  private String message;
  private String error;
}
