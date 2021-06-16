package ru.sysout.jwt.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import ru.sysout.jwt.model.MyUser;
import ru.sysout.jwt.repository.MyUserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

  private final MyUserRepository dao;

  public CustomUserDetailsService(MyUserRepository dao) {
    this.dao = dao;
  }

  @Override
  public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
    MyUser myUser = dao.findByLogin(userName);
    if (myUser == null) {
      throw new UsernameNotFoundException("Unknown user: " + userName);
    }
    return User.builder()
        .username(myUser.getLogin())
        .password(myUser.getPassword())
        .roles(myUser.getRole())
        .build();
  }
}