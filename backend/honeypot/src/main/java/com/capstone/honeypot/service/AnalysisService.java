package com.capstone.honeypot.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;

/**
 * 외부 분석 서비스(FastAPI) 호출.
 *
 * <p>이 서비스는 <b>선택</b> 구성이다. 프로젝트의 주 분석 경로는 Elasticsearch
 * 사이드카(ml-classifier → llm-analyzer)이고, 여기는 Spring 으로 직접 적재되는
 * 로그에만 쓰인다. 그래서 미구성 상태가 정상일 수 있다.
 *
 * <p>이전 구현은 호출이 실패하면 {@code riskScore 50 / MEDIUM} 같은 값을 만들어
 * 돌려줬고, 호출부가 그것을 그대로 저장했다. 실패가 <b>그럴듯한 분석 결과로
 * 둔갑</b>해 DB 에 남는 셈이라, 화면에서는 진짜 분석과 구분되지 않았다.
 * 지금은 실패하면 {@link Optional#empty()} 를 돌려주고, 저장 여부는 호출부가 정한다.
 */
@Slf4j
@Service
public class AnalysisService {

    private final RestTemplate restTemplate;
    private final String fastapiUrl;
    private final boolean enabled;

    public AnalysisService(
            RestTemplateBuilder builder,
            @Value("${fastapi.url:}") String fastapiUrl,
            @Value("${fastapi.enabled:true}") boolean enabled) {
        // 기본 RestTemplate 은 타임아웃이 없다. 상대가 응답하지 않으면 서블릿
        // 스레드가 무한정 붙잡힌다 — 적재 API 전체가 같이 멈춘다.
        this.restTemplate = builder
                .connectTimeout(Duration.ofSeconds(2))
                .readTimeout(Duration.ofSeconds(5))
                .build();
        this.fastapiUrl = fastapiUrl == null ? "" : fastapiUrl.trim();
        this.enabled = enabled && !this.fastapiUrl.isBlank();

        if (!this.enabled) {
            log.info("외부 분석 서비스가 구성되지 않았습니다. 적재된 로그는 분석 결과 없이 저장됩니다 "
                    + "(주 분석 경로는 ES 사이드카입니다).");
        }
    }

    /**
     * @return 분석 결과. 서비스가 없거나 호출이 실패하면 {@code empty} —
     *         <b>추측한 값을 채워 넣지 않는다.</b>
     */
    public Optional<Map<String, Object>> analyze(String attackType, String payload, String ipAddress) {
        if (!enabled) {
            return Optional.empty();
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Map<String, Object>> request = new HttpEntity<>(Map.of(
                "attackType", attackType == null ? "" : attackType,
                "payload", payload == null ? "" : payload,
                "ipAddress", ipAddress == null ? "" : ipAddress
        ), headers);

        try {
            ResponseEntity<Map> response =
                    restTemplate.postForEntity(fastapiUrl + "/analyze", request, Map.class);
            Map<String, Object> body = response.getBody();
            return body == null ? Optional.empty() : Optional.of(body);
        } catch (RestClientException e) {
            // 적재 자체는 성공시킨다 — 분석은 부가 기능이고, 실패를 이유로
            // 원본 로그를 잃으면 안 된다.
            log.warn("외부 분석 호출 실패 ({}): {}", fastapiUrl, e.getMessage());
            return Optional.empty();
        }
    }
}
