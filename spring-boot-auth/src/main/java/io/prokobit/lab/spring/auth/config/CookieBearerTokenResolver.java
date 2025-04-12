package io.prokobit.lab.spring.auth.config;

import static io.prokobit.lab.spring.auth.config.SecurityConfig.ACCESS_TOKEN_COOKIE_NAME;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class CookieBearerTokenResolver implements BearerTokenResolver {

  @Override
  public String resolve(HttpServletRequest request) {

    String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
    if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
      return authHeader.substring(7);
    }

    if (request.getCookies() != null) {
      for (Cookie cookie : request.getCookies()) {
        if (ACCESS_TOKEN_COOKIE_NAME.equals(cookie.getName())) {
          return cookie.getValue();
        }
      }
    }

    return null;
  }
}
