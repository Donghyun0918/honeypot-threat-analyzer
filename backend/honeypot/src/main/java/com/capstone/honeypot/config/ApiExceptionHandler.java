package com.capstone.honeypot.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.NoSuchElementException;

/**
 * API 예외를 상태 코드와 메시지로 바꾼다.
 *
 * <p>이게 없으면 서비스에서 던진 {@code IllegalArgumentException} 이 그대로
 * 컨테이너까지 올라가 Spring 의 {@code /error} 로 포워딩되는데, 그 경로가
 * 인증 대상이라 <b>모든 오류가 403 으로 뭉개진다</b>. "이미 사용 중인
 * 이메일입니다" 같은 메시지가 클라이언트에 전혀 도달하지 못했다.
 *
 * <p>응답 형태는 프론트가 그대로 표시할 수 있게 단순하게 둔다:
 * {@code { "message": "...", "status": 400 }}
 */
@Slf4j
@RestControllerAdvice
public class ApiExceptionHandler {

    /** 잘못된 입력 — 메시지를 그대로 보여준다(사용자에게 쓸모 있는 문장이다). */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> badRequest(IllegalArgumentException e) {
        return body(HttpStatus.BAD_REQUEST, e.getMessage());
    }

    /** 조회 대상 없음. */
    @ExceptionHandler(NoSuchElementException.class)
    public ResponseEntity<Map<String, Object>> notFound(NoSuchElementException e) {
        return body(HttpStatus.NOT_FOUND, blankTo(e.getMessage(), "요청한 리소스를 찾을 수 없습니다."));
    }

    /** 예상하지 못한 오류 — 내부 사정을 클라이언트에 흘리지 않고 로그로만 남긴다. */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> unexpected(Exception e) {
        log.error("처리하지 못한 예외", e);
        return body(HttpStatus.INTERNAL_SERVER_ERROR, "서버에서 오류가 발생했습니다.");
    }

    private static ResponseEntity<Map<String, Object>> body(HttpStatus status, String message) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("message", blankTo(message, status.getReasonPhrase()));
        payload.put("status", status.value());
        payload.put("timestamp", Instant.now().toString());
        return ResponseEntity.status(status).body(payload);
    }

    private static String blankTo(String value, String fallback) {
        return (value == null || value.isBlank()) ? fallback : value;
    }
}
