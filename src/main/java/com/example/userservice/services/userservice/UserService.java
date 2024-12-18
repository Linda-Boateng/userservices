package com.example.userservice.services.userservice;

import com.example.userservice.records.UserDto;

public interface UserService {
    /**
     * Create a new user
     * @param userDto
     * @return UserDto object of the created user
     */
    UserDto createUser(UserDto userDto);

    /**
     * Login a user
     * @param userDto
     * @return UserDto object of the logged-in user
     */
    UserDto loginUser(UserDto userDto);

    /**
     * Get user details
     * @param email user email
     * @return UserDto object of the user
     */
    UserDto getUser(UserDto email);

    /**
     * Get user details
     * @param email user email  (social user)
     * @return UserDto object of the user
     */
    UserDto getSocialUserDetails(String email);
}
