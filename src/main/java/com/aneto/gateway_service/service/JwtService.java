
package com.aneto.gateway_service.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Service
public class JwtService {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtService.class);
    private SecretKey secretKey;

    @Value("${jwt.secret}")
    private String secret;

    // Construtor vazio - o Spring injeta o @Value após a criação do bean
    public JwtService() {
        LOGGER.info("JwtService criado. Aguardando injeção de propriedades...");
    }
// Método executado APÓS a injeção de dependências
    @PostConstruct
    public void init() {
        LOGGER.info("JwtService INICIALIZADO. Lendo chave secreta...");

        if (secret == null || secret.length() < 32) {
            LOGGER.error("Chave secreta JWT ausente ou muito curta! Valor: {}", secret);
            throw new IllegalStateException("Chave secreta inválida. Verifique jwt.secret no application.yaml");
        }

        // CORREÇÃO CRÍTICA: Remova o MessageDigest e use a String diretamente.
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        LOGGER.info("Chave JWT carregada com sucesso.");

    }

    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isValid(String token) {
        try {
            extractAllClaims(token);
            return true;
        } catch (SignatureException e) {
            LOGGER.error("ERRO JWT (SIGNATURE): Assinatura inválida (Chave errada!).");
            return false;
        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            LOGGER.error("ERRO JWT (EXPIRED): Token expirado.");
            return false;
        } catch (Exception e) {
            LOGGER.error("ERRO JWT (GERAL): Falha ao decodificar/validar o token: {}", e.getMessage());
            return false;
        }
    }
}