package com.capstone.honeypot.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtFilter jwtFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        // 정적 페이지 허용
                        .requestMatchers(
                                "/",
                                "/dashboard.html",
                                "/test.html",
                                "/css/**",
                                "/js/**",
                                "/images/**"
                        ).permitAll()

                        // 인증 없이 접근 가능한 API
                        .requestMatchers(
                                // 예외 처리 중 Spring 이 포워딩하는 경로. 인증 대상으로
                                // 두면 모든 오류가 403 으로 바뀐다.
                                "/error",
                                "/api/users/signup",
                                "/api/users/login",
                                "/api/users/check-email",
                                "/api/health",
                                "/api/internal/**",
                                // threat-console (Phase 1: 조회 + Export)
                                "/api/overview",
                                "/api/ml-stats",
                                "/api/llm-recent",
                                "/api/llm-stats",
                                "/api/export/**"
                        ).permitAll()

                        // 나머지는 인증 필요
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}