package com.example.spring_authentication_service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.stream.Collectors;

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  private AuthenticationManager authenticationManager;

  private final JwtConfig jwtConfig;

  public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager, JwtConfig jwtConfig) {
    this.authenticationManager = authenticationManager;
    this.jwtConfig = jwtConfig;

    this.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher(jwtConfig.getUri(),"POST"));
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

    try{
      UserCredentials userCredentials = new ObjectMapper().readValue(request.getInputStream(),UserCredentials.class);
      UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
          userCredentials.getUserName(),userCredentials.getPassword(), Collections.emptyList());

      return authenticationManager.authenticate(authenticationToken);
    } catch (IOException e){
      throw new RuntimeException(e);
    }
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
    Long now = System.currentTimeMillis();
    String token = Jwts.builder()
        .setSubject(authResult.getName())
        .claim("authorities",authResult.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
        .setIssuedAt(new Date((now)))
        .setExpiration(new Date(now+jwtConfig.getExpiration()*1000))
        .signWith(SignatureAlgorithm.ES512,jwtConfig.getSecret().getBytes())
        .compact();
    response.addHeader(jwtConfig.getHeader(),jwtConfig.getPrefix()+token);
  }

  private static class UserCredentials {
    private String userName, password;

    public void setUserName(String userName) {
      this.userName = userName;
    }

    public void setPassword(String password) {
      this.password = password;
    }

    public String getUserName() {
      return userName;
    }

    public String getPassword() {
      return password;
    }
  }
}
