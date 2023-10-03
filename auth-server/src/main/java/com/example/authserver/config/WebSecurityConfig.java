package com.example.authserver.config;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@AllArgsConstructor
public class WebSecurityConfig {

  private final CorsConfigurationSource corsConfigurationSource;

  @Bean
  // A Spring Security filter chain for authentication.
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    return http
        .cors(corsConfigurer -> {
          corsConfigurer.configurationSource(corsConfigurationSource);
        })
        // Form login handles the redirect to the login page from the
			  // authorization server filter chain
        .formLogin(formLoginCustomizer -> {
        })
        .authorizeHttpRequests(requestsCustomizer -> {
          requestsCustomizer.anyRequest().authenticated();
        })
        .build();
  }

  @Bean
  public UserDetailsService userDetailsService() {
    var u1 = User
        .withUsername("bill")
        .password("{noop}12345")
        .authorities("read")
        .build();
    return new InMemoryUserDetailsManager(u1);
  }

  /*
  @Bean
  public PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance(); // only for demonstrations
  }
  */
}
