package com.aneto.gateway_service.security;

import com.aneto.gateway_service.service.JwtService;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import java.util.stream.Collectors;

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

    // Configuração vazia (necessária para AbstractGatewayFilterFactory)
    public static class Config {
        // Nada a configurar de momento
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getPath().toString();

            // Verificação mais robusta para ignorar a segurança nesta rota
            if (path.contains("/confirmar-alerta") || path.contains("/api/auth")) {
                LOGGER.info("Rota pública detectada no Gateway: {}", path);
                return chain.filter(exchange);
            }
            // 1. Verifica se tem o Header de Autorização
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return this.onError(exchange, "Header de Autorização não encontrado.", HttpStatus.UNAUTHORIZED);
            }

            // 2. Extrai e valida o Token
            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            String token = null;

            if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
                token = authHeader.substring(BEARER_PREFIX.length());
            }

            if (token == null || !jwtService.isValid(token)) {
                return this.onError(exchange, "Token JWT inválido ou expirado.", HttpStatus.UNAUTHORIZED);
            }

            // 3. Extrai as Claims e adiciona os headers
            Claims claims = jwtService.extractAllClaims(token);
            // Prossegue com a requisição, adicionando os Headers
            ServerWebExchange mutatedExchange = addClaimsToHeaders(exchange, claims);

            return chain.filter(mutatedExchange);
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String reason, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        // Adiciona um header com o motivo do erro (Não é padrão no Spring Gateway)
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
        @SuppressWarnings("unchecked")
        List<String> rolesList = claims.get("roles", List.class);

        // 🔑 CORREÇÃO CRÍTICA: Garantir que a Role tem o prefixo "ROLE_" (padrão do Spring Security)
        List<String> prefixedRoles = (rolesList != null)
                ? rolesList.stream()
                .map(role -> role.toUpperCase().startsWith("ROLE_") ? role.toUpperCase() : "ROLE_" + role.toUpperCase())
                .collect(Collectors.toList())
                : List.of("ROLE_ESTAGIARIO"); // Fallback seguro (e com o prefixo)

        String rolesHeader = String.join(",", prefixedRoles);
        LOGGER.info("Roles enviadas para o serviço de destino: {}", rolesHeader);


        // Constrói uma nova requisição com os novos headers
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header("X-User-Id", userId)
                // ✅ Agora envia no formato correto (ROLE_ADMIN, ROLE_ESTAGIARIO, etc.)
                .header("X-User-Roles", rolesHeader)
                // Remove o token de autorização para segurança, se desejar (opcional)
                //.headers(headers -> headers.remove(HttpHeaders.AUTHORIZATION))
                .build();

        // Retorna um novo ServerWebExchange com a requisição modificada
        return exchange.mutate().request(mutatedRequest).build();
    }
}