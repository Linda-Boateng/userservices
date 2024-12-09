package com.example.userservice.records;

import com.example.userservice.models.Role;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDto {
   private Long id;
   private String firstname;
   private String lastname;
   private String email;
   private String password;
   private Role role;
   private String token;
}
