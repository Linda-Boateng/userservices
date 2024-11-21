package com.example.userservice.services.userservice;

import com.example.userservice.records.UserDto;

public interface UserService {
    UserDto createUser(UserDto userDto);

    UserDto loginUser(UserDto userDto);
}
