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
                        // 인증 없이 접근 가능한 API
                        .requestMatchers(
                                // 예외 처리 중 Spring 이 포워딩하는 경로. 인증 대상으로
                                // 두면 모든 오류가 403 으로 바뀐다.
                                "/error",
                                "/api/users/signup",
                                "/api/users/login",
                                "/api/users/check-email",
                                "/api/health",
                                // 서비스 간 호출. Spring Security 대신 X-Service-Token
                                // 공유 비밀로 InternalController 안에서 검사한다.
                                "/api/internal/**"
                        ).permitAll()

                        // threat-console 흡수분(조회·Export)은 인증을 요구한다.
                        //
                        // 이전에는 permitAll 이었다. 그 상태에서 /api/llm-recent 는
                        // 토큰 없이도 공격자 IP·허니팟·한국어 위협 분석 전문을 그대로
                        // 돌려줬고, /api/export/** 는 전체를 CSV 로 내려줬다. 화면에는
                        // 로그인 관문이 있었지만 데이터는 그 뒤에 있지 않았다 —
                        // 프론트에서 로그인을 판정하던 결함(10장)과 같은 종류다.
                        //
                        // 프론트 프록시는 이미 Authorization 헤더를 전달하고 있고,
                        // 독립형 threat-console 은 ES 를 직접 읽으므로 영향이 없다.
                        .requestMatchers(
                                "/api/overview",
                                "/api/ml-stats",
                                "/api/llm-recent",
                                "/api/llm-patterns",
                                "/api/llm-explain",
                                "/api/exposure",
                                // 내 자산 목록. 본인 것만 다루지만, 애초에
                                // 로그인하지 않은 사람이 닿을 이유가 없다.
                                "/api/assets",
                                "/api/llm-stats",
                                "/api/export/**"
                        ).authenticated()

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