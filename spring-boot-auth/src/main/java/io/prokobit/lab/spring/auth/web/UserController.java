package io.prokobit.lab.spring.auth.web;

import java.util.Map;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

  @GetMapping("/user")
  public Map<String, Object> user(@AuthenticationPrincipal Jwt principal) {
    return principal.getClaims();
  }
}
