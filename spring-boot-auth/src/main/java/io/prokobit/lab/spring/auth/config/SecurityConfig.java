package io.prokobit.lab.spring.auth.config;

import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Log4j2
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
@Profile("!test")
public class SecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    // spotless:off
    return http.csrf(AbstractHttpConfigurer::disable)
        .authorizeHttpRequests((requests) -> requests
            .requestMatchers("/", "/logout", "/error", "/webjars/**").permitAll()
            .anyRequest().authenticated())
//        .exceptionHandling(e ->
//            e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
//        )
        .oauth2Login((login) -> login
            .loginPage("/")
            .redirectionEndpoint((endpoint) -> endpoint.baseUri("/login/oauth2/callback/*"))
            .defaultSuccessUrl("/")
        )
        .logout(l -> l
            .logoutSuccessUrl("/").permitAll()
        )
//        .sessionManagement(s -> s
//            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//        )
        .build();
    // spotless:on
  }
}
