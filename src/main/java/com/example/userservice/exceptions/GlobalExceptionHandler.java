package com.example.userservice.exceptions;

import com.example.userservice.dtos.ErrorResponseDto;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(
            value = {
                    DuplicateException.class
            })
    ResponseEntity<ErrorResponseDto> handleBadRequest(
            RuntimeException exception, HttpServletRequest httpServletRequest) {
        return new ResponseEntity<>(
                new ErrorResponseDto(httpServletRequest.getRequestURI(), exception.getMessage()),
                HttpStatus.CONFLICT);
    }

    @ExceptionHandler(BadCredentialsException.class)
    ResponseEntity<ErrorResponseDto> handleBadCredentials(
            BadCredentialsException exception, HttpServletRequest httpServletRequest) {
        return new ResponseEntity<>(
                new ErrorResponseDto(httpServletRequest.getRequestURI(), exception.getMessage()),
                HttpStatus.BAD_REQUEST);
    }
}
