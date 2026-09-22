package com.capstone.honeypot.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.http.converter.HttpMessageNotReadableException;

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

    /**
     * 요청이 형식을 안 지킨 경우 — 필수 헤더·파라미터 누락, 본문 파싱 실패.
     *
     * <p>이걸 잡지 않으면 아래 {@code Exception} 핸들러로 떨어져 <b>500</b> 이 된다.
     * 실제로 {@code X-Service-Token} 헤더 없이 {@code /api/internal/attack-log} 를
     * 부르면 500 이 나왔다 — 잘못은 클라이언트에 있는데 서버 장애처럼 보이고,
     * 로그에도 "처리하지 못한 예외"로 쌓여 진짜 장애와 섞인다.
     */
    @ExceptionHandler({
            MissingRequestHeaderException.class,
            MissingServletRequestParameterException.class,
            HttpMessageNotReadableException.class,
    })
    public ResponseEntity<Map<String, Object>> malformedRequest(Exception e) {
        return body(HttpStatus.BAD_REQUEST, "요청 형식이 올바르지 않습니다.");
    }

    /**
     * 예상하지 못한 오류 — 내부 사정을 클라이언트에 흘리지 않고 로그로만 남긴다.
     *
     * <p>단, Spring MVC 가 던지는 표준 예외는 <b>자기 상태 코드를 들고 온다</b>
     * ({@link ErrorResponse} 구현체). 이 캐치올이 그걸 무시하고 전부 500 으로
     * 뭉개고 있었다 — {@code ExceptionHandlerExceptionResolver} 가
     * {@code DefaultHandlerExceptionResolver} 보다 먼저 돌기 때문에 여기서
     * 가로채면 Spring 의 기본 매핑이 아예 실행되지 않는다.
     *
     * <p>실제 증상: 없는 경로를 부르면 {@code NoResourceFoundException} 이
     * 404 를 들고 오는데 응답은 500 "서버에서 오류가 발생했습니다" 였다.
     * 클라이언트 잘못인데 서버 장애처럼 보이고, 로그에도 "처리하지 못한 예외"
     * 로 쌓여 진짜 장애와 섞인다. 잘못된 HTTP 메서드(405)·지원하지 않는
     * Content-Type(415) 도 같은 이유로 500 이었다.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> unexpected(Exception e) {
        if (e instanceof ErrorResponse er) {
            HttpStatusCode code = er.getStatusCode();
            HttpStatus status = HttpStatus.resolve(code.value());
            if (status == null) {
                status = HttpStatus.INTERNAL_SERVER_ERROR;
            }
            // 4xx 는 클라이언트 잘못이므로 경고까지만 — 진짜 장애 로그를 오염시키지 않는다.
            if (status.is5xxServerError()) {
                log.error("서버 오류 ({})", status.value(), e);
            } else {
                log.warn("클라이언트 요청 오류 ({}): {}", status.value(), e.getMessage());
            }
            return body(status, messageFor(status));
        }
        log.error("처리하지 못한 예외", e);
        return body(HttpStatus.INTERNAL_SERVER_ERROR, "서버에서 오류가 발생했습니다.");
    }

    /** 상태 코드별 한국어 문구. 예외 메시지를 그대로 흘리면 내부 경로가 드러난다. */
    private static String messageFor(HttpStatus status) {
        return switch (status) {
            case NOT_FOUND -> "요청한 경로를 찾을 수 없습니다.";
            case METHOD_NOT_ALLOWED -> "허용되지 않은 요청 방식입니다.";
            case UNSUPPORTED_MEDIA_TYPE -> "지원하지 않는 요청 형식입니다.";
            case NOT_ACCEPTABLE -> "응답 형식을 맞출 수 없습니다.";
            case BAD_REQUEST -> "요청 형식이 올바르지 않습니다.";
            // 로그인 연속 실패 차단(LoginAttemptService). 영어 reason phrase 가
            // 그대로 화면에 뜨면 사용자는 무슨 일인지 알 수 없다. 남은 시간까지
            // 알려주면 친절하지만, 그건 차단이 언제 풀리는지 재보게 해주는 셈이라
            // 여기서는 말하지 않는다 — 정확한 수치는 서버 로그에 남는다.
            case TOO_MANY_REQUESTS -> "로그인 시도가 너무 많습니다. 잠시 후 다시 시도해주세요.";
            default -> status.is5xxServerError()
                    ? "서버에서 오류가 발생했습니다."
                    : status.getReasonPhrase();
        };
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
