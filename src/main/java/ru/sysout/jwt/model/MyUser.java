package ru.sysout.jwt.model;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Entity
@Data
@RequiredArgsConstructor
public class MyUser {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  long id;
  private String login;
  private String password;
  private String position;
  private String role;

}