package com.capstone.honeypot.controller;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.sql.Connection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 의존하는 것이 실제로 살아 있는지 본다.
 *
 * <p>전에는 {@code return "backend is running"} 이 전부였다. 프로세스가 떠 있기만
 * 하면 무조건 200 이므로 <b>무엇도 확인하지 않는 검사</b>였다. 2026-09-15 에
 * {@code dev-postgres} 가 18시간 죽어 있는 동안(작업 로그 §1) 이 엔드포인트는
 * 내내 200 을 돌려주고 있었다 — 죽은 것을 살아 있다고 말하는 검사는 없는 것보다
 * 나쁘다. 그걸 믿고 다른 데를 보게 만들기 때문이다.
 *
 * <p>DB 와 Elasticsearch 를 직접 두드리고, 하나라도 끊겼으면 <b>503</b> 을 준다.
 * compose 헬스체크가 이 엔드포인트를 보므로 {@code docker compose ps} 의
 * {@code unhealthy} 로 드러난다.
 *
 * <p>인증은 걸지 않는다(SecurityConfig 에서 permitAll). 대신 <b>무엇이 왜 끊겼는지</b>
 * 는 내보내지 않는다 — 상태와 짧은 이름만 준다. 예외 메시지에는 호스트·포트·드라이버
 * 버전이 섞여 나오는데, 인증 없이 열린 문으로 내부 구조를 알려줄 이유가 없다.
 * 자세한 것은 서버 로그에 남는다.
 */
@RestController
@RequiredArgsConstructor
@Slf4j
public class HealthController {

    private final DataSource dataSource;
    private final ElasticsearchClient es;

    /** DB 응답을 기다리는 한도(초). 이보다 오래 걸리면 끊긴 것으로 본다. */
    private static final int DB_TIMEOUT_SEC = 2;

    @GetMapping("/api/health")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> body = new LinkedHashMap<>();
        boolean db = checkDb();
        boolean elastic = checkEs();
        boolean up = db && elastic;

        body.put("status", up ? "ok" : "degraded");
        body.put("db", db ? "ok" : "down");
        body.put("elasticsearch", elastic ? "ok" : "down");

        return ResponseEntity.status(up ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE)
                .body(body);
    }

    private boolean checkDb() {
        // isValid 는 커넥션이 실제로 쓸 수 있는지를 드라이버가 판단한다.
        // 풀에서 꺼내오기만 하면 끊긴 커넥션도 손에 쥘 수 있다.
        try (Connection c = dataSource.getConnection()) {
            return c.isValid(DB_TIMEOUT_SEC);
        } catch (Exception e) {
            log.warn("health: DB 확인 실패 — {}", e.toString());
            return false;
        }
    }

    private boolean checkEs() {
        try {
            return es.ping().value();
        } catch (Exception e) {
            log.warn("health: Elasticsearch 확인 실패 — {}", e.toString());
            return false;
        }
    }
}
