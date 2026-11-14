package com.election.voteservice.security;

import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    private final SecretKey key;

    public JwtService(@Value("${JWT_SECRET}") String secret) {
        byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
        if (secretBytes.length < 32) {
            throw new IllegalArgumentException(
                    "JWT_SECRET must contain at least 256 bits (32 UTF-8 bytes)");
        }
        this.key = Keys.hmacShaKeyFor(secretBytes);
    }

    public Claims extractAllClaims(String token) {

        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extractUsername(String token) {

        return extractAllClaims(token).getSubject();
    }

    public Long extractUserId(String token) {

        Object userId =
                extractAllClaims(token).get("userId");

        if (userId == null) {
            return null;
        }

        return ((Number) userId).longValue();
    }

    public String extractRole(String token) {

        Object role =
                extractAllClaims(token).get("role");

        if (role == null) {
            return null;
        }

        return role.toString();
    }

    public boolean isTokenValid(String token) {

        try {
            extractAllClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}