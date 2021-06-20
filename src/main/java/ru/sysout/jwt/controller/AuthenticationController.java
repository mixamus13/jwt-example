package ru.sysout.jwt.controller;

import lombok.val;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import ru.sysout.jwt.security.AuthRequest;
import ru.sysout.jwt.security.AuthResponse;
import ru.sysout.jwt.security.JWTUtil;

@RestController
public class AuthenticationController {

  private final AuthenticationManager authenticationManager;
  private final JWTUtil jwtTokenUtil;

  public AuthenticationController(AuthenticationManager authenticationManager, JWTUtil jwtTokenUtil) {
    this.authenticationManager = authenticationManager;
    this.jwtTokenUtil = jwtTokenUtil;
  }

  @PostMapping("/authenticate")
  @ResponseStatus(HttpStatus.OK)
  public AuthResponse createAuthenticationToken(@RequestBody AuthRequest authRequest) {
    Authentication authentication;
    try {
      authentication = authenticationManager.authenticate(
          new UsernamePasswordAuthenticationToken(authRequest.getName(), authRequest.getPassword()));
      System.out.println(authentication);
    } catch (BadCredentialsException e) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Имя или from неправильны", e);
    }
    /* при создании токена в него кладется username как Subject и список authorities как кастомный claim */
    val jwt = jwtTokenUtil.generateToken((UserDetails) authentication.getPrincipal());

    return new AuthResponse(jwt);
  }
}