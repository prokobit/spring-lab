package io.prokobit.lab.spring.auth.config;

import static io.prokobit.lab.spring.auth.config.CookieBearerTokenResolver.BEARER_TOKEN_COOKIE_NAME;

import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

@Log4j2
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
@Profile("!test")
@AllArgsConstructor
public class SecurityConfig {

  private final CustomOAuth2SuccessHandler successHandler;
  private final BearerTokenResolver bearerTokenResolver;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    // spotless:off
    return http
        .csrf( csrf -> csrf.ignoringRequestMatchers("/**"))
        .sessionManagement(s -> s
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        )
        .authorizeHttpRequests(requests -> requests
            .requestMatchers("/", "/logout", "/error", "/webjars/**").permitAll()
            .anyRequest().authenticated())
        .exceptionHandling(e -> e
            .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
        )
        .oauth2ResourceServer(oauth2 -> oauth2
            .jwt(Customizer.withDefaults())
            .bearerTokenResolver(bearerTokenResolver)
        )
        .oauth2Login(login -> login
            .loginPage("/")
            .authorizationEndpoint(endpoint -> endpoint
                .baseUri("/login/oauth2/authorization")
            )
            .redirectionEndpoint(endpoint -> endpoint
                .baseUri("/login/oauth2/callback/*")
            )
            .successHandler(successHandler)
        )
        .logout(c -> c
            .deleteCookies(BEARER_TOKEN_COOKIE_NAME)
            .logoutSuccessUrl("/")
            .permitAll()
        )
        .build();
    // spotless:on
  }
}
