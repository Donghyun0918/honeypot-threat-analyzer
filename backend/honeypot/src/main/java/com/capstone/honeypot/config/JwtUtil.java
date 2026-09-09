package com.capstone.honeypot.config;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;

/**
 * JWT 발급·검증.
 *
 * <p>서명 키는 소스에 두지 않는다. 키가 코드에 박혀 있으면 저장소를 볼 수 있는
 * 누구나 임의의 사용자로 로그인한 토큰을 만들 수 있다. {@code JWT_SECRET}
 * 환경변수로 주입하고, 없으면 기동 시 임의 키를 만들어 쓰되 경고를 남긴다.
 * (임의 키는 재기동하면 바뀌므로 기존 토큰이 무효가 된다 — 운영에서는
 * 반드시 환경변수를 설정해야 한다는 뜻이다.)
 */
@Slf4j
@Component
public class JwtUtil {

    /** HS256 최소 키 길이. 이보다 짧으면 jjwt 가 거부한다. */
    private static final int MIN_SECRET_BYTES = 32;

    @Value("${jwt.secret:}")
    private String configuredSecret;

    @Value("${jwt.expiration-minutes:60}")
    private long expirationMinutes;

    private SecretKey key;

    @PostConstruct
    void init() {
        byte[] secret;
        if (configuredSecret == null || configuredSecret.isBlank()) {
            secret = new byte[MIN_SECRET_BYTES];
            new SecureRandom().nextBytes(secret);
            log.warn("JWT_SECRET 이 설정되지 않아 임의 키를 생성했습니다. "
                    + "재기동하면 발급된 토큰이 모두 무효가 됩니다. "
                    + "운영 환경에서는 JWT_SECRET 을 설정하십시오 "
                    + "(예: openssl rand -base64 48).");
        } else {
            secret = decode(configuredSecret);
            if (secret.length < MIN_SECRET_BYTES) {
                throw new IllegalStateException(
                        "JWT_SECRET 이 너무 짧습니다: " + secret.length + " 바이트. "
                                + MIN_SECRET_BYTES + " 바이트 이상이어야 합니다.");
            }
        }
        this.key = Keys.hmacShaKeyFor(secret);
    }

    /** base64 로 주어졌으면 디코드하고, 아니면 평문 바이트로 쓴다. */
    private static byte[] decode(String value) {
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException notBase64) {
            return value.getBytes(StandardCharsets.UTF_8);
        }
    }

    public String generateToken(String email) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + expirationMinutes * 60_000L))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String getEmail(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
}
