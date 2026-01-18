package com.aneto.gateway_service.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

// language: java
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Value("${app.security.cors.allowed-origins}")
    private List<String> allowedOrigins;

    @Value("${app.security.cors.allowed-methods}")
    private List<String> allowedMethods;

    @Value("${app.security.cors.allowed-headers}")
    private List<String> allowedHeaders;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**").permitAll()
                        .pathMatchers("/api/auth/**").permitAll()
                        .pathMatchers("/actuator/**").permitAll()

                        // 🚨 GARANTIR QUE ESTA ROTA ESPECÍFICA ESTÁ ABERTA PARA GET E POST
                        .pathMatchers("/api/v1/eventos/*/confirmar-alerta").permitAll()

                        // Se o resto da tua API exige login, aqui mudarias para .authenticated()
                        .pathMatchers("/api/**").permitAll()

                        .anyExchange().authenticated()
                );

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // // Se o seu React roda em http://localhost:5173, use esse valor.
        configuration.setAllowedOrigins(allowedOrigins);
        configuration.setAllowedMethods(allowedMethods);
        configuration.setAllowedHeaders(allowedHeaders);
        configuration.setAllowCredentials(true);
        // 5. MÁXIMO DE IDADE (Cache dos cabeçalhos CORS)
        configuration.setMaxAge(3600L); // 1 hora

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}