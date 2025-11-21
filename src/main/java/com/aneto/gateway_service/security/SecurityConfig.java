package com.aneto.gateway_service.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
// language: java
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {

        http.csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        // Rota 1: Permite Auth (login/registo)
                        .pathMatchers("/api/auth/**").permitAll()

                        // Rota 2: Permite todas as rotas da API.
                        // A segurança será aplicada via application.yml (JwtAuthFilter)
                        .pathMatchers("/api/**").permitAll()

                        // Apenas endpoints que realmente não têm filtros de gateway devem ser bloqueados aqui
                        .anyExchange().authenticated() // Mantenha esta linha para garantir que nenhum endpoint é esquecido, mas será ignorada para /api/**
                );

        return http.build();
    }
}