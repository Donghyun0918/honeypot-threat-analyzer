package com.capstone.honeypot.config;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import org.springframework.http.HttpMethod;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 예외 → 상태 코드 매핑 회귀 테스트.
 *
 * <p>없는 경로를 부르면 500 "서버에서 오류가 발생했습니다" 가 나왔다.
 * {@code @ExceptionHandler(Exception.class)} 캐치올이
 * {@code ExceptionHandlerExceptionResolver} 단계에서 먼저 잡아,
 * Spring 의 기본 상태 코드 매핑이 아예 실행되지 않았기 때문이다.
 * 404 하나가 아니라 <b>표준 예외 전부</b>가 500 으로 뭉개지고 있었다.
 *
 * <p>클라이언트 잘못이 서버 장애처럼 보이면 로그에서 진짜 장애와 섞인다.
 */
class ApiExceptionHandlerTest {

    private final ApiExceptionHandler handler = new ApiExceptionHandler();

    private static int 상태(ResponseEntity<Map<String, Object>> r) {
        return r.getStatusCode().value();
    }

    private static String 메시지(ResponseEntity<Map<String, Object>> r) {
        return String.valueOf(r.getBody().get("message"));
    }

    @Test
    void 없는_경로는_404_다() {
        var e = new NoResourceFoundException(HttpMethod.GET, "/api/없는것");
        var r = handler.unexpected(e);
        assertEquals(404, 상태(r));
        assertEquals(404, r.getBody().get("status"));
    }

    @Test
    void 잘못된_메서드는_405_다() {
        var r = handler.unexpected(new HttpRequestMethodNotSupportedException("POST"));
        assertEquals(405, 상태(r));
    }

    @Test
    void 지원하지_않는_형식은_415_다() {
        var r = handler.unexpected(new HttpMediaTypeNotSupportedException("text/plain"));
        assertEquals(415, 상태(r));
    }

    /** ErrorResponse 가 아닌 진짜 예상 밖 예외만 500 이어야 한다. */
    @Test
    void 예상하지_못한_예외만_500_이다() {
        var r = handler.unexpected(new IllegalStateException("무언가 터졌다"));
        assertEquals(500, 상태(r));
    }

    /**
     * 예외 메시지를 그대로 흘리면 내부 경로가 드러난다.
     * NoResourceFoundException 의 메시지는 "No static resource api/..." 다.
     */
    @Test
    void 내부_메시지를_클라이언트에_흘리지_않는다() {
        var e = new NoResourceFoundException(HttpMethod.GET, "/api/internal/secret-path");
        String m = 메시지(handler.unexpected(e));
        assertFalse(m.contains("secret-path"), "내부 경로가 응답에 새어 나갔다: " + m);
        assertFalse(m.contains("static resource"), "프레임워크 메시지가 그대로 나갔다: " + m);
        assertTrue(m.contains("찾을 수 없습니다"));
    }

    @Test
    void 서버오류_응답도_내부_사정을_말하지_않는다() {
        String m = 메시지(handler.unexpected(new IllegalStateException("DB password=hunter2")));
        assertFalse(m.contains("hunter2"));
    }

    /** 잘못된 입력은 400 이고 메시지는 사용자에게 쓸모 있어야 한다. */
    @Test
    void 잘못된_입력은_메시지를_그대로_보여준다() {
        var r = handler.badRequest(new IllegalArgumentException("이미 사용 중인 이메일입니다"));
        assertEquals(400, 상태(r));
        assertEquals("이미 사용 중인 이메일입니다", 메시지(r));
    }
}
