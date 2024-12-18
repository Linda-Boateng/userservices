package com.example.userservice.services.userservice;

import static com.example.userservice.util.ConstantStrings.USER_ALREADY_EXIST;

import com.example.userservice.exceptions.DuplicateException;
import com.example.userservice.exceptions.NotFoundException;
import com.example.userservice.models.Role;
import com.example.userservice.models.User;
import com.example.userservice.records.UserDto;
import com.example.userservice.repository.UserRepository;
import com.example.userservice.services.jwtservice.JwtService;
import java.util.Map;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {

  private final UserRepository userRepository;
  private final AuthenticationManager authenticationManager;
  private final JwtService jwtService;
  private final PasswordEncoder passwordEncoder;

  public UserServiceImpl(
      UserRepository userRepository,
      AuthenticationManager authenticationManager,
      JwtService jwtService,
      PasswordEncoder passwordEncoder) {
    this.userRepository = userRepository;
    this.authenticationManager = authenticationManager;
    this.jwtService = jwtService;
    this.passwordEncoder = passwordEncoder;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public UserDto createUser(UserDto userDto) {
    User user = userRepository.findByEmail(userDto.getEmail());
    if (user != null) {
      throw new DuplicateException(USER_ALREADY_EXIST);
    }
    user =
        User.builder()
            .firstname(userDto.getFirstname())
            .lastname(userDto.getLastname())
            .email(userDto.getEmail())
            .password(passwordEncoder.encode(userDto.getPassword()))
            .role(Role.USER)
            .build();
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

    /**
     * {@inheritDoc}
     */
  @Override
  public UserDto loginUser(UserDto userDto) {

    Authentication authentication =
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(userDto.getEmail(), userDto.getPassword()));
    SecurityContextHolder.getContext().setAuthentication(authentication);

    User user = userRepository.findByEmail(userDto.getEmail());
    if (user == null) {
      throw new NotFoundException("User not found");
    }
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
        userDto.getFirstname(),
        userDto.getLastname(),
        user.getEmail(),
        user.getPassword(),
        user.getRole(),
        jwtToken);
  }

    /**
     * {@inheritDoc}
     */
  @Override
  public UserDto getUser(UserDto email) {

    User user = userRepository.findByEmail(email.getEmail());
    return new UserDto(
        user.getId(),
        user.getFirstname(),
        user.getLastname(),
        user.getEmail(),
        user.getPassword(),
        user.getRole(),
        null);
  }

    /**
     * {@inheritDoc}
     */
  @Override
  public UserDto getSocialUserDetails(String email) {

    return null;
  }
}
