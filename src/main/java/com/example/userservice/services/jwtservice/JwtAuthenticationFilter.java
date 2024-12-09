package com.example.userservice.services.jwtservice;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.userservice.dtos.JwtErrorResponseDto;
import com.example.userservice.exceptions.BadCredentialsException;
import com.example.userservice.models.Role;
import com.example.userservice.models.User;
import com.example.userservice.records.UserDto;
import com.example.userservice.services.userservice.UserCreationService;
import com.example.userservice.services.userservice.UserDetailsServiceImpl;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

@Service
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
  public static final String AUTHORIZATION_HEADER = "Authorization";
  public static final String TOKEN_PREFIX = "Bearer ";
  public static final String INVALID_TOKEN = "Invalid_Token";
  private final UserDetailsServiceImpl userDetailsService;
  private final UserCreationService userService;
  private static final String SECRET =
      "pejFQ7VibeTQXuMs0T/XiNFUHz5ZrITrzG9LBTDujsCEOqE6iR6+X8R8rP0V88Gc";

  @Override
  public void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain)
      throws ServletException, IOException {

    try {
      String jwt = extractJwtFromRequest(request);
      if (!jwt.isEmpty()) {
        DecodedJWT decodedJWT = decodeJwt(jwt);
        String firstname = decodedJWT.getSubject();
        String email = decodedJWT.getClaim("email").asString();
        String lastname = decodedJWT.getClaim("family_name").asString();
        request.setAttribute("firstname", firstname);

        UserDto userDto = new UserDto();
        userDto.setEmail(email);
        userDto.setFirstname(firstname);
        userDto.setLastname(lastname);

        System.out.println("email: " + email);
        System.out.println("firstname: " + firstname);
        System.out.println("lastname: " + lastname);

        if (request.getRequestURI().contains("api/v1/admin")
            && !decodedJWT.getClaim("role").asString().equals("ADMIN")) {
          response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
          return;
        }
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
          UserDetails userDetails = userDetailsService.loadUserByUsername(email);
          if (userDetails == null) {
            userService.createUser(userDto);
            userDetails = userDetailsService.loadUserByUsername(email);
          }
          UsernamePasswordAuthenticationToken authentication =
              new UsernamePasswordAuthenticationToken(
                  userDetails, null, userDetails.getAuthorities());
          authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

          SecurityContextHolder.getContext().setAuthentication(authentication);
        }
      }

    } catch (BadCredentialsException e) {
      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      new ObjectMapper()
          .writeValue(
              response.getOutputStream(), new JwtErrorResponseDto("Please login", e.getMessage()));
      return;
    } catch (JWTVerificationException e) {
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      new ObjectMapper()
          .writeValue(
              response.getOutputStream(), new JwtErrorResponseDto("Please login", e.getMessage()));
      return;
    }
    filterChain.doFilter(request, response);
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    String path = request.getServletPath();
    return path.equals("/api/auth/register")
        || path.equals("/api/auth/login")
        || path.contains("/oauth2/")
        || path.contains("/.well-known/jwks.json");
  }

  private DecodedJWT decodeJwt(String jwt) {
    String algorithm = JWT.decode(jwt).getAlgorithm();

    if ("HS256".equalsIgnoreCase(algorithm)) {
      Algorithm hmacAlgorithm = Algorithm.HMAC256(Base64.getDecoder().decode(SECRET));
      JWTVerifier verifier = JWT.require(hmacAlgorithm).build();
      return verifier.verify(jwt);
    } else if ("RS256".equalsIgnoreCase(algorithm)) {
      return JWT.decode(jwt);
    } else {
      throw new JWTVerificationException("Unsupported algorithm: " + algorithm);
    }
  }

  private UserDto getProfileDetailsGoogle(DecodedJWT decodedJWT) {
    UserDto user = new UserDto();
    user.setEmail(decodedJWT.getClaim("email").asString());
    user.setFirstname(decodedJWT.getClaim("name").asString());
    user.setLastname(decodedJWT.getClaim("given_name").asString());
    user.setRole(Role.USER);

    return user;
  }

  public String extractJwtFromRequest(HttpServletRequest request) {
    String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
    if (bearerToken != null && bearerToken.startsWith(TOKEN_PREFIX)) {
      return bearerToken.substring(TOKEN_PREFIX.length());
    }
    throw new BadCredentialsException(INVALID_TOKEN);
  }
}
