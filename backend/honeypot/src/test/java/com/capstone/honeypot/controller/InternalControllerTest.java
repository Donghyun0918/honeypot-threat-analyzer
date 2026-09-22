package com.capstone.honeypot.controller;

import com.capstone.honeypot.dto.InternalAttackLogRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 내부 수집 엔드포인트의 인증·검증 회귀 테스트.
 *
 * <p>이 엔드포인트는 Spring Security 에서 {@code permitAll} 이고 공유 비밀
 * 하나로만 지켜진다. 그래서 <b>토큰 검사가 무엇보다 먼저</b> 와야 하고,
 * 입력 검증은 그다음이다.
 *
 * <p>검증이 없던 시절 본문 {@code {}} 를 보내면 500 이 났는데, 로그를 보면
 * 검증 전에 <b>사용자 행 INSERT 를 먼저 시도</b>했다 — 형식만 맞으면 계정이
 * 자동 생성되는 경로에 검증이 없었다는 뜻이다.
 */
class InternalControllerTest {

    private InternalController controller;

    @BeforeEach
    void 준비() {
        // 협력자를 null 로 둔다. 아래 테스트들은 전부 토큰 검사나 입력 검증에서
        // 끝나므로 리포지토리·서비스에 닿지 않는다. 닿는다면 NPE 로 터지는데,
        // 그건 "검증 전에 쓰기를 시도했다" 는 뜻이라 오히려 잡아야 할 신호다.
        controller = new InternalController(null, null, null, null);
        ReflectionTestUtils.setField(controller, "serviceToken", "올바른토큰");
    }

    private static InternalAttackLogRequest 요청(String user, String type, String ip) {
        var r = new InternalAttackLogRequest();
        r.setUsername(user);
        r.setAttackType(type);
        r.setIpAddress(ip);
        return r;
    }

    @Test
    void 틀린_토큰은_403_이고_본문을_보기_전에_막는다() {
        ResponseEntity<?> r = controller.saveAttackLog("틀린토큰", 요청(null, null, null));
        assertEquals(403, r.getStatusCode().value());
    }

    /**
     * 토큰이 틀리고 본문도 비었을 때 400 이 아니라 403 이어야 한다.
     * 400 이 먼저 나가면 토큰 없이도 본문 스키마를 떠볼 수 있다.
     */
    @Test
    void 인증_실패가_입력_검증보다_먼저다() {
        ResponseEntity<?> r = controller.saveAttackLog("틀린토큰", 요청(null, null, null));
        assertEquals(403, r.getStatusCode().value());
        assertNotEquals(400, r.getStatusCode().value());
    }

    @Test
    void 빈_본문은_400_이고_빠진_항목을_알려준다() {
        ResponseEntity<?> r = controller.saveAttackLog("올바른토큰", 요청(null, null, null));
        assertEquals(400, r.getStatusCode().value());
        String m = String.valueOf(((Map<?, ?>) r.getBody()).get("message"));
        assertTrue(m.contains("username"), m);
        assertTrue(m.contains("attackType"), m);
        assertTrue(m.contains("ipAddress"), m);
    }

    @Test
    void 일부만_빠져도_그것만_짚는다() {
        ResponseEntity<?> r = controller.saveAttackLog("올바른토큰", 요청("sensor1", null, null));
        assertEquals(400, r.getStatusCode().value());
        String m = String.valueOf(((Map<?, ?>) r.getBody()).get("message"));
        assertFalse(m.contains("username"), "이미 채워진 항목을 빠졌다고 했다: " + m);
        assertTrue(m.contains("attackType"), m);
    }

    /** 공백만 있는 값은 채워진 것이 아니다 — 그대로 두면 name=" " 인 계정이 생긴다. */
    @Test
    void 공백_문자열은_빈_값으로_친다() {
        ResponseEntity<?> r = controller.saveAttackLog("올바른토큰", 요청("   ", "scan", "1.2.3.4"));
        assertEquals(400, r.getStatusCode().value());
        assertTrue(String.valueOf(((Map<?, ?>) r.getBody()).get("message")).contains("username"));
    }

    /**
     * 공유 비밀이 비어 있으면 임의 값으로 채워 <b>모두 거부</b>해야 한다.
     * 예전 기본값 "honeypot-internal-token" 처럼 고정값을 두면 저장소를 읽은
     * 사람 누구나 공격 로그를 밀어넣을 수 있다.
     */
    @Test
    void 공유_비밀이_비면_아무_토큰도_통과하지_못한다() {
        ReflectionTestUtils.setField(controller, "serviceToken", "");
        controller.토큰확인();
        for (String 시도 : new String[]{"", "honeypot-internal-token", "admin", "null"}) {
            assertEquals(403, controller.saveAttackLog(시도, 요청("a", "b", "c")).getStatusCode().value(),
                    "빈 설정에서 '" + 시도 + "' 가 통과했다");
        }
    }
}
