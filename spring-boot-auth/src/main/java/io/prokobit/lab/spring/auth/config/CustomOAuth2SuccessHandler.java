package io.prokobit.lab.spring.auth.config;

import static io.prokobit.lab.spring.auth.config.SecurityConfig.ACCESS_TOKEN_COOKIE_NAME;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
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

    String accessToken = client.getAccessToken().getTokenValue();

    ResponseCookie cookie =
        ResponseCookie.from(ACCESS_TOKEN_COOKIE_NAME, accessToken)
            .path("/")
            .httpOnly(true)
            .secure(false) // TODO: enable tls
            .sameSite("Strict")
            .maxAge(Duration.ofHours(1))
            .build();

    response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

    response.sendRedirect("/");
  }
}
