package com.example.userservice.services.userservice;

import static com.example.userservice.util.ConstantStrings.USER_ALREADY_EXIST;

import com.example.userservice.exceptions.DuplicateException;
import com.example.userservice.models.Role;
import com.example.userservice.models.User;
import com.example.userservice.records.UserDto;
import com.example.userservice.repository.UserRepository;
import com.example.userservice.services.jwtservice.JwtService;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
  private final UserRepository userRepository;
  private final AuthenticationManager authenticationManager;
  private final JwtService jwtService;
  private final PasswordEncoder passwordEncoder;

  @Override
  public UserDto createUser(UserDto userDto) {
    Optional<User> userExist = userRepository.findByEmail(userDto.email());
    if (userExist.isPresent()) {
      throw new DuplicateException(USER_ALREADY_EXIST);
    }
    User user =
        new User(
            userDto.firstname(),
            userDto.lastname(),
            userDto.email(),
            passwordEncoder.encode(userDto.password()),
            Role.USER);
    User createdUser = userRepository.save(user);
    var jwtToken = jwtService.generateToken(user);
    return new UserDto(
        createdUser.getId(),
        createdUser.getFirstname(),
        createdUser.getLastname(),
        createdUser.getEmail(),
        createdUser.getPassword(),
        createdUser.getRole(),
        jwtToken);
  }

  @Override
  public UserDto loginUser(UserDto userDto) {
    Authentication authentication =
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(userDto.email(), userDto.password()));
    SecurityContextHolder.getContext().setAuthentication(authentication);

    User user = userRepository.findByEmail(userDto.email()).orElseThrow();
    Map<String, Object> claims =
        Map.of(
            "email",
            user.getEmail(),
            "firstname",
            user.getFirstname(),
            "lastname",
            user.getLastname(),
            "role",
            user.getRole().toString());
    var jwtToken = jwtService.generateToken(claims, user);
    return new UserDto(
        user.getId(),
        userDto.firstname(),
        userDto.lastname(),
        user.getEmail(),
        user.getPassword(),
        user.getRole(),
        jwtToken);
  }
}
