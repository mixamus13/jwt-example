package ru.sysout.jwt.security;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthRequest {

  private String name;
  private String password;

}