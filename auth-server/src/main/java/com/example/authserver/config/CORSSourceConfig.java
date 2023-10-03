package com.example.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.List;

@Configuration
public class CORSSourceConfig {

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfigurationSource source = s -> {
      CorsConfiguration cc = new CorsConfiguration();
      cc.setAllowCredentials(true);
      cc.setAllowedOrigins(List.of("http://127.0.0.1:3000"));
      cc.setAllowedHeaders(List.of("*"));
      cc.setAllowedMethods(List.of("*"));
      return cc;
    };
    return source;
  }

}
