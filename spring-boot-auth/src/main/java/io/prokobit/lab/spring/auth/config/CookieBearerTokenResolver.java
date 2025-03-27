package io.prokobit.lab.spring.auth.config;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;
import java.util.stream.Stream;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.stereotype.Component;

@Component
public class CookieBearerTokenResolver implements BearerTokenResolver {

  static final String BEARER_TOKEN_COOKIE_NAME = HttpHeaders.AUTHORIZATION;

  private final BearerTokenResolver fallbackBearerTokenResolver = new DefaultBearerTokenResolver();

  @Override
  public String resolve(HttpServletRequest request) {
    return Optional.ofNullable(request.getCookies()).stream()
        .flatMap(Stream::of)
        .filter(cookie -> BEARER_TOKEN_COOKIE_NAME.equals(cookie.getName()))
        .map(Cookie::getValue)
        .findAny()
        .orElseGet(() -> fallbackBearerTokenResolver.resolve(request));
  }
}
