package com.example.userservice.controller;

import com.example.userservice.records.UserDto;
import com.example.userservice.services.userservice.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/auth")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @Operation(
            summary = "Register user",
            description = "Register a new user in the system",
            responses = {
                    @ApiResponse(responseCode = "200", description = "User registered successfully"),
            })
    @PostMapping("/register")
    public ResponseEntity<UserDto> register(@RequestBody UserDto userDto) {
        return new ResponseEntity<>(userService.createUser(userDto), HttpStatus.CREATED);
    }

    @Operation(
            summary = "Login user",
            description = "Login a user in the system",
            responses = {
                    @ApiResponse(responseCode = "200", description = "User logged in successfully"),
            })
    @PostMapping("/login")
    public ResponseEntity<UserDto> login(@RequestBody UserDto userDto) {
        return new ResponseEntity<>(userService.loginUser(userDto), HttpStatus.OK);
    }

    @Operation(
            summary = "Get user",
            description = "Get user details",
            security = @SecurityRequirement(name = "JWT Bearer Token"),
            responses = {
                    @ApiResponse(responseCode = "200", description = "User details fetched successfully"),
            })
    @GetMapping("/user")
    public ResponseEntity<UserDto> getUser(@RequestBody UserDto email) {
        return new ResponseEntity<>(userService.getUser(email), HttpStatus.OK);
    }

}
