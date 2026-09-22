package com.capstone.honeypot.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 로그인 실패를 세어 연속 시도를 막는다.
 *
 * <p><b>왜 필요한가.</b> BCrypt 로 해싱하고 JWT 를 쓰지만, 비밀번호를 <b>몇 번
 * 틀려도 되는지</b>에 제한이 없었다. 허니팟이 받아낸 공격 중 Brute Force 가
 * 2,168건이고 그걸 탐지 성과로 내세우는 프로젝트다 — 정작 자기 로그인문이
 * 무제한이면 앞뒤가 맞지 않는다.
 *
 * <h2>왜 IP 로 세지 않는가</h2>
 *
 * 흔한 방식은 이메일과 <b>클라이언트 IP</b> 를 함께 세는 것이다. 이 구조에서는
 * 쓸 수 없고, 억지로 쓰면 <b>지금보다 나빠진다</b>:
 *
 * <ul>
 *   <li>브라우저는 Spring 을 직접 부르지 않는다. Next.js 서버 라우트가 중계하므로
 *       ({@code frontend/src/app/api/auth/[action]/route.ts}) Spring 이 보는
 *       주소는 <b>누가 로그인하든 프론트 컨테이너 하나</b>다. 그걸로 세면 한 사람의
 *       실패 5번이 <b>전원을 잠근다.</b></li>
 *   <li>프론트가 실제 IP 를 실어 보내면 되지만, Next 15 는 {@code req.ip} 를 없앴고
 *       브라우저가 Next 에 직접 붙으므로 {@code X-Forwarded-For} 도 없다 —
 *       프론트 자신이 클라이언트 IP 를 모른다.</li>
 *   <li>그렇다고 백엔드가 {@code X-Forwarded-For} 를 믿을 수도 없다. Spring 포트
 *       (8091)가 공개돼 있어 직접 부르면서 헤더를 원하는 값으로 넣으면 그만이다 —
 *       <b>공격자가 자기 차단을 스스로 지울 수 있는 제한</b>은 제한이 아니다.</li>
 * </ul>
 *
 * 그래서 <b>이메일 단위로만</b> 센다. 관측된 출처는 로그에만 남긴다(어차피 프론트
 * 주소지만, 누군가 Spring 을 직접 두드리면 그건 드러난다).
 *
 * <p>프론트가 나중에 믿을 만한 클라이언트 IP 를 넘겨줄 수 있게 되면(리버스 프록시를
 * 앞에 두고 그 프록시만 신뢰하는 식) 그때 IP 키를 더한다.
 *
 * <h2>계정 잠금이 아니라 속도 제한이다</h2>
 *
 * 이메일로만 세면 <b>남의 계정을 일부러 잠글 수 있다</b>(DoS). 그래서 영구 잠금이
 * 아니라 <b>몇 분 뒤 저절로 풀리는 차단</b>을 쓴다. 공격자가 얻는 것은 "몇 분 지연"
 * 뿐이고, 무제한 시도는 막힌다.
 *
 * <p><b>한계 — 프로세스 메모리다.</b> 재기동하면 초기화되고 인스턴스 간 공유가
 * 안 된다. 프론트의 추론 관문(작업 로그 §25)과 같은 전제이고, 여러 대로 늘릴 때
 * 함께 Postgres·Redis 로 옮긴다.
 */
@Service
@Slf4j
public class LoginAttemptService {

    /** 이 횟수만큼 연속 실패하면 차단된다. */
    @Value("${login.max-attempts:5}")
    private int maxAttempts;

    /** 실패 기록이 유지되는 창(분). 이 시간 동안 조용하면 카운터가 사라진다. */
    @Value("${login.window-minutes:5}")
    private int windowMinutes;

    /** 차단이 지속되는 시간(분). */
    @Value("${login.block-minutes:5}")
    private int blockMinutes;

    private record 기록(int 실패수, Instant 마지막실패) {}

    private final Map<String, 기록> 기록들 = new ConcurrentHashMap<>();

    /** 차단 중이면 남은 시간(초), 아니면 0. */
    public long 남은차단초(String email) {
        String 키 = 키(email);
        기록 r = 기록들.get(키);
        if (r == null) return 0;

        Duration 지난시간 = Duration.between(r.마지막실패(), Instant.now());

        if (r.실패수() < maxAttempts) {
            // 창이 지나도록 조용했으면 없던 일로 한다.
            if (지난시간.compareTo(Duration.ofMinutes(windowMinutes)) > 0) {
                기록들.remove(키);
            }
            return 0;
        }

        long 남음 = Duration.ofMinutes(blockMinutes).minus(지난시간).toSeconds();
        if (남음 <= 0) {
            기록들.remove(키);   // 차단 해제 — 다시 0 부터 센다
            return 0;
        }
        return 남음;
    }

    public void 실패기록(String email, String 관측출처) {
        기록들.compute(키(email), (k, r) -> {
            if (r == null) return new 기록(1, Instant.now());
            // 창이 지났으면 새로 센다. 하루 종일 드문드문 틀린 사람이
            // 어느 순간 차단되는 일이 없어야 한다.
            boolean 창밖 = Duration.between(r.마지막실패(), Instant.now())
                    .compareTo(Duration.ofMinutes(windowMinutes)) > 0;
            return new 기록(창밖 ? 1 : r.실패수() + 1, Instant.now());
        });
        log.warn("로그인 실패 — email={} 출처={}", 가림(email), 관측출처);
    }

    public void 성공기록(String email) {
        기록들.remove(키(email));
    }

    private static String 키(String email) {
        return email == null ? "" : email.trim().toLowerCase();
    }

    /** 로그에 계정을 통째로 남기지 않는다. */
    private static String 가림(String email) {
        if (email == null || email.isBlank()) return "(없음)";
        int at = email.indexOf('@');
        if (at <= 1) return "***";
        return email.charAt(0) + "***" + email.substring(at);
    }
}
