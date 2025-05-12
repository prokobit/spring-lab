package io.prokobit.lab.spring.auth.config;

import static io.prokobit.lab.spring.auth.config.CookieBearerTokenResolver.BEARER_TOKEN_COOKIE_NAME;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
public class CustomOAuth2SuccessHandler implements AuthenticationSuccessHandler {

  @Autowired private OAuth2AuthorizedClientService authorizedClientService;

  @Override
  public void onAuthenticationSuccess(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException, ServletException {

    OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
    OAuth2AuthorizedClient client =
        authorizedClientService.loadAuthorizedClient(
            oauthToken.getAuthorizedClientRegistrationId(), oauthToken.getName());

    ResponseCookie cookie =
        ResponseCookie.from(BEARER_TOKEN_COOKIE_NAME, client.getAccessToken().getTokenValue())
            .path("/")
            .httpOnly(true)
            .secure(true)
            .sameSite("Strict")
            .maxAge(Duration.between(Instant.now(), client.getAccessToken().getExpiresAt()))
            .build();

    response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    response.sendRedirect("/");
  }
}
