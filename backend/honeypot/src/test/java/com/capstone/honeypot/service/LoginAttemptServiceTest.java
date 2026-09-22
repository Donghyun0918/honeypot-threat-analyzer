package com.capstone.honeypot.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 로그인 연속 시도 차단.
 *
 * <p>{@code @Value} 필드는 스프링 컨텍스트 없이는 0 이므로 리플렉션으로 채운다.
 * 컨텍스트를 띄우면 DB·ES 가 필요해지고, 그러면 이 테스트는 "환경이 갖춰졌을 때만
 * 도는 테스트" 가 되어 아무도 안 돌린다.
 */
class LoginAttemptServiceTest {

    private LoginAttemptService 서비스;

    private static final String EMAIL = "demo@jsp.test";
    private static final String 출처 = "172.18.0.9";

    @BeforeEach
    void setUp() {
        서비스 = new LoginAttemptService();
        ReflectionTestUtils.setField(서비스, "maxAttempts", 5);
        ReflectionTestUtils.setField(서비스, "windowMinutes", 5);
        ReflectionTestUtils.setField(서비스, "blockMinutes", 5);
    }

    @Test
    @DisplayName("한도 미만 실패는 통과시킨다")
    void 한도_미만은_통과() {
        for (int i = 0; i < 4; i++) {
            서비스.실패기록(EMAIL, 출처);
        }
        assertEquals(0, 서비스.남은차단초(EMAIL));
    }

    @Test
    @DisplayName("한도에 도달하면 차단하고 남은 시간을 알려준다")
    void 한도_도달시_차단() {
        for (int i = 0; i < 5; i++) {
            서비스.실패기록(EMAIL, 출처);
        }
        long 남음 = 서비스.남은차단초(EMAIL);
        assertTrue(남음 > 0, "차단돼야 한다");
        assertTrue(남음 <= 300, "차단 시간(5분)을 넘지 않아야 한다: " + 남음);
    }

    @Test
    @DisplayName("로그인에 성공하면 카운터가 지워진다")
    void 성공하면_초기화() {
        for (int i = 0; i < 4; i++) {
            서비스.실패기록(EMAIL, 출처);
        }
        서비스.성공기록(EMAIL);

        // 지워졌다면 여기서 4번 더 틀려도 아직 차단되지 않아야 한다.
        for (int i = 0; i < 4; i++) {
            서비스.실패기록(EMAIL, 출처);
        }
        assertEquals(0, 서비스.남은차단초(EMAIL));
    }

    @Test
    @DisplayName("다른 계정은 서로 영향을 주지 않는다")
    void 계정별로_센다() {
        for (int i = 0; i < 5; i++) {
            서비스.실패기록(EMAIL, 출처);
        }
        assertTrue(서비스.남은차단초(EMAIL) > 0);
        assertEquals(0, 서비스.남은차단초("other@jsp.test"),
                "한 계정이 막혔다고 다른 계정까지 막으면 전체 서비스 거부가 된다");
    }

    @Test
    @DisplayName("대소문자와 공백이 달라도 같은 계정으로 센다")
    void 이메일_정규화() {
        for (int i = 0; i < 3; i++) {
            서비스.실패기록(EMAIL, 출처);
        }
        for (int i = 0; i < 2; i++) {
            서비스.실패기록("  DEMO@JSP.TEST  ", 출처);
        }
        assertTrue(서비스.남은차단초(EMAIL) > 0,
                "표기만 바꿔 한도를 우회할 수 있으면 제한이 아니다");
    }

    @Test
    @DisplayName("차단 시간이 지나면 저절로 풀린다")
    void 시간이_지나면_해제() {
        ReflectionTestUtils.setField(서비스, "blockMinutes", 0);   // 즉시 만료
        for (int i = 0; i < 5; i++) {
            서비스.실패기록(EMAIL, 출처);
        }
        assertEquals(0, 서비스.남은차단초(EMAIL),
                "영구 잠금이면 남의 계정을 영원히 잠글 수 있다");
    }

    @Test
    @DisplayName("창이 지난 뒤의 실패는 처음부터 다시 센다")
    void 창을_벗어나면_리셋() {
        ReflectionTestUtils.setField(서비스, "windowMinutes", 0);   // 모든 실패가 창 밖
        for (int i = 0; i < 10; i++) {
            서비스.실패기록(EMAIL, 출처);
        }
        assertEquals(0, 서비스.남은차단초(EMAIL),
                "하루에 몇 번씩 드문드문 틀리는 사람이 차단되면 안 된다");
    }

    @Test
    @DisplayName("이메일이 null 이어도 죽지 않는다")
    void null_이메일() {
        assertDoesNotThrow(() -> {
            서비스.실패기록(null, 출처);
            서비스.남은차단초(null);
            서비스.성공기록(null);
        });
    }
}
