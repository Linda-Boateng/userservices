package com.example.userservice.records;

import com.example.userservice.models.Role;

public record UserDto(Long id, String firstname, String lastname, String email, String password, Role role, String token) {}
