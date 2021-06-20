package ru.sysout.jwt.security;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.val;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.sysout.jwt.service.CustomUserDetailsService;

@Component
public class JWTFilter extends OncePerRequestFilter {

  private final JWTUtil jwtUtil;
  private final CustomUserDetailsService userDetailsService;

  public JWTFilter(JWTUtil jwtUtil, CustomUserDetailsService userDetailsService) {
    this.jwtUtil = jwtUtil;
    this.userDetailsService = userDetailsService;
  }

  /**
   * если подпись не совпадает с вычисленной, то SignatureException если подпись некорректная (не парсится) то MalformedJwtException если подпись истекла по
   * времени,  то ExpiredJwtException
   */
  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {

    final String authorizationHeader = request.getHeader("Authorization");
    String username = null;
    String jwt = null;

    if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
      jwt = authorizationHeader.substring(7);
      username = jwtUtil.extractUsername(jwt);
    }

    if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

      val commaSeparatedListOfAuthorities = jwtUtil.extractAuthorities(jwt);
      val authorities = AuthorityUtils
          .commaSeparatedStringToAuthorityList(commaSeparatedListOfAuthorities);
      val usernamePasswordAuthenticationToken =
          new UsernamePasswordAuthenticationToken(username, null, authorities);
      SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
    }
    chain.doFilter(request, response);
  }
}