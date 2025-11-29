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

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {

        http
                // CONFIGURAÇÃO CORS PARA RESOLVER 'Failed to fetch'
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // 🔑 CORREÇÃO PARA RESOLVER O ERRO 'Cannot resolve symbol'
                .csrf(ServerHttpSecurity.CsrfSpec::disable) // Usa a sintaxe Lambda mais segura e clara

                .authorizeExchange(exchanges -> exchanges
                        // Rota 1: Permite Auth (login/registo)
                        .pathMatchers("/api/auth/**").permitAll()

                        // Rota 2: Permite todas as rotas da API.
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
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-User-Roles", "X-User-Id"));
        configuration.setAllowCredentials(true);
        // 5. MÁXIMO DE IDADE (Cache dos cabeçalhos CORS)
        configuration.setMaxAge(3600L); // 1 hora

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}