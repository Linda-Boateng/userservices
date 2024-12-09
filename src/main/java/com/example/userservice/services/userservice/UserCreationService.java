package com.example.userservice.services.userservice;

import com.example.userservice.exceptions.DuplicateException;
import com.example.userservice.models.Role;
import com.example.userservice.models.User;
import com.example.userservice.records.UserDto;
import com.example.userservice.repository.UserRepository;
import com.example.userservice.services.jwtservice.JwtService;

import static com.example.userservice.util.ConstantStrings.USER_ALREADY_EXIST;
import org.springframework.stereotype.Service;


@Service
public class UserCreationService {
    private final UserRepository userRepository;

    public UserCreationService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public void createUser(UserDto userDto) {
        User user = userRepository.findByEmail(userDto.getEmail());
        if (user != null) {
            throw new DuplicateException(USER_ALREADY_EXIST);
        }
        user =
                User.builder()
                        .firstname(userDto.getFirstname())
                        .lastname(userDto.getLastname())
                        .email(userDto.getEmail())
                        .role(Role.USER)
                        .build();
        User createdUser = userRepository.save(user);

        new UserDto(
                createdUser.getId(),
                createdUser.getFirstname(),
                createdUser.getLastname(),
                createdUser.getEmail(),
                createdUser.getPassword(),
                createdUser.getRole(), null);
    }
}
