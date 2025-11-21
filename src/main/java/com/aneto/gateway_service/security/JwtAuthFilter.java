package com.aneto.gateway_service.security;

import com.aneto.gateway_service.service.JwtService;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class JwtAuthFilter extends AbstractGatewayFilterFactory<JwtAuthFilter.Config> {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtAuthFilter.class);
    private static final String BEARER_PREFIX = "Bearer ";

    // Injeção por Construtor (Forma mais segura e obrigatória)
    private final JwtService jwtService;

    // O Spring irá injetar automaticamente o JwtService aqui
    public JwtAuthFilter(JwtService jwtService) {
        super(Config.class);
        this.jwtService = jwtService;
        LOGGER.info("JwtAuthFilter inicializado com JwtService injetado.");
    }

    public static class Config {
        // Exemplo: se precisar de configuração via application.yml
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {

            String authHeader = exchange.getRequest()
                    .getHeaders()
                    .getFirst(HttpHeaders.AUTHORIZATION);

            if (!hasBearerToken(authHeader)) {
                LOGGER.debug("Requisição sem token Bearer.");
                return unauthorized(exchange, "Token ausente ou formato inválido.");
            }

            String token = extractToken(authHeader);
            // 1. Validação do JWT
            if (!jwtService.isValid(token)) {
                // O log de erro detalhado da falha (Signature/Expired) está dentro do JwtService
                return unauthorized(exchange, "Token inválido ou expirado. Verifique logs do Gateway.");
            }

            // 2. Extrai claims e adiciona ao header
            Claims claims = jwtService.extractAllClaims(token);
            return chain.filter(addClaimsToHeaders(exchange, claims));
        };
    }

    private boolean hasBearerToken(String authHeader) {
        return authHeader != null && authHeader.startsWith(BEARER_PREFIX);
    }

    private String extractToken(String authHeader) {
        return authHeader.substring(BEARER_PREFIX.length()).trim();
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String reason) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        // Opcional: Adicionar um body JSON ou header com o motivo do erro (Não é padrão no Spring Gateway)
        response.getHeaders().add("X-Auth-Error", reason);
        return response.setComplete();
    }

    /**
     * Extrai o ID do usuário (subject) e as roles do JWT e adiciona-os
     * como headers no request para os serviços downstream.
     */
    private ServerWebExchange addClaimsToHeaders(ServerWebExchange exchange, Claims claims) {

        // Obtém o Subject (SUB) como o ID/Username do usuário
        String userId = claims.getSubject();

        // Obtém as Roles (o campo "roles" deve ser configurado na geração do token no Auth Service)
        // O valor padrão de List.of("USER") é um fallback caso o campo não exista
        @SuppressWarnings("unchecked")
        List<String> rolesList = claims.get("roles", List.class);
        String rolesHeader = rolesList != null ? String.join(",", rolesList) : "ESTAGIARIO";

        // Constrói uma nova requisição com os novos headers
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header("X-User-Id", userId)
                .header("X-User-Roles", rolesHeader)
                // Remove o token de autorização para segurança, se desejar (opcional)
                .headers(headers -> headers.remove(HttpHeaders.AUTHORIZATION))
                .build();

        // Retorna um novo ServerWebExchange com a requisição modificada
        return exchange.mutate().request(mutatedRequest).build();
    }
}