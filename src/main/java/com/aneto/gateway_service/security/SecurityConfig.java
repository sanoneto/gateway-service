package com.aneto.gateway_service.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Value("${app.security.cors.allowed-origins:http://localhost:5173,http://localhost:4173}")
    private String allowedOriginsRaw;

    @Value("${app.security.cors.allowed-methods:GET,POST,PUT,DELETE,OPTIONS,PATCH}")
    private String allowedMethodsRaw;

    @Value("${app.security.cors.allowed-headers:*}")
    private String allowedHeadersRaw;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                // 1. Desativa CSRF
                .csrf(ServerHttpSecurity.CsrfSpec::disable)

                // 2. Associa o CorsConfigurationSource
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // 3. Regras de Autorização
                .authorizeExchange(exchanges -> exchanges
                        // PERMISSÃO CRÍTICA: Permite SEMPRE requisições HTTP OPTIONS (Preflight)
                        .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // Rotas Públicas
                        .pathMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        .pathMatchers("/api/auth/**").permitAll()
                        .pathMatchers("/api/**").permitAll()

                        .anyExchange().authenticated()
                )
                .build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Faz parse das origens do application.yml
        List<String> origins = Arrays.stream(allowedOriginsRaw.split(","))
                .map(String::trim)
                .toList();

        List<String> methods = Arrays.stream(allowedMethodsRaw.split(","))
                .map(String::trim)
                .toList();

        List<String> headers = allowedHeadersRaw.equals("*")
                ? List.of("*")
                : Arrays.stream(allowedHeadersRaw.split(",")).map(String::trim).toList();

        // Configura permissões dinâmicas (funciona com portas variáveis como 4173 e 5173)
        configuration.setAllowedOriginPatterns(List.of(
                "http://localhost:*",
                "https://*.vercel.app",
                "https://www.sanoneto.com",
                "https://www.liveproact.com",
                "http://treg-aneto.com*"
        ));

        configuration.setAllowedMethods(methods);
        configuration.setAllowedHeaders(headers);
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}