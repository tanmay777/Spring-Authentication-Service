package com.example.spring_authentication_service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;


public class JwtTokenAuthenticationFilter extends OncePerRequestFilter {

  private final JwtConfig jwtConfig;

  public JwtTokenAuthenticationFilter(JwtConfig jwtConfig) {
    this.jwtConfig = jwtConfig;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
    String header = httpServletRequest.getHeader(jwtConfig.getHeader());
    if((header == null) || !header.startsWith(jwtConfig.getPrefix())){
      filterChain.doFilter(httpServletRequest,httpServletResponse);
      return;
    }

    String token = header.replace(jwtConfig.getPrefix(),"");

    try{
      Claims claims = Jwts.parser()
          .setSigningKey(jwtConfig.getSecret().getBytes())
          .parseClaimsJws(token)
          .getBody();

      String userName = claims.getSubject();

      if(userName != null){
        List<String> authorities = (List<String>) claims.get("authorities");

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userName
            , null,authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));

        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
      }
    } catch (Exception e){
      SecurityContextHolder.clearContext();
    }

  }
}
