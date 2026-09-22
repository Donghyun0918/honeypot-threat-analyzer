package com.capstone.honeypot.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 대시보드·보고서의 모든 수치가 나오는 서비스.
 *
 * <p>ES 질의 자체는 여기서 검증하지 않는다 — 살아 있는 ES 가 필요해지고, 그러면
 * "환경이 갖춰졌을 때만 도는 테스트" 가 되어 아무도 안 돌린다. 대신 <b>ES 가
 * 해주지 않는 계산</b>, 즉 입력 정리와 결과 가공을 본다. §23-4 에서 집계가 전량
 * 실패했을 때 화면은 조용히 빈 값을 보여줬는데, 그런 자리들이 여기다.
 *
 * <p>ES 를 타는 경로는 스택을 띄운 뒤
 * {@code integration-tests/verify_threat_console.sh} 로 확인한다.
 */
class ThreatConsoleServiceTest {

    // ── 창(window) 기본값 ────────────────────────────────────────────────

    @Test
    @DisplayName("since 가 없으면 기본 창을 쓴다")
    void 창_기본값() {
        assertEquals("now-7d", ThreatConsoleService.창(null, "now-7d"));
        assertEquals("now-7d", ThreatConsoleService.창("", "now-7d"));
        assertEquals("now-7d", ThreatConsoleService.창("   ", "now-7d"));
    }

    @Test
    @DisplayName("since 를 주면 그대로 쓴다")
    void 창_지정값() {
        assertEquals("now-1y", ThreatConsoleService.창("now-1y", "now-7d"));
    }

    // ── 크기 제한 ────────────────────────────────────────────────────────

    @Test
    @DisplayName("size 가 없으면 기본값")
    void 크기_기본값() {
        assertEquals(20, ThreatConsoleService.크기(null, 20, 100));
    }

    @Test
    @DisplayName("상한을 넘기면 상한으로 자른다")
    void 크기_상한() {
        assertEquals(100, ThreatConsoleService.크기(100000, 20, 100),
                "그대로 넘기면 ES 집계가 통째로 무거워진다");
    }

    @Test
    @DisplayName("0 이나 음수는 1 로 올린다")
    void 크기_하한() {
        assertEquals(1, ThreatConsoleService.크기(0, 20, 100),
                "terms 집계에 0 을 넘기면 오류가 난다 — 입력 하나로 조회가 깨진다");
        assertEquals(1, ThreatConsoleService.크기(-5, 20, 100));
    }

    // ── 포트 정규화 ──────────────────────────────────────────────────────

    @Test
    @DisplayName("중복 포트는 한 번만 센다")
    void 포트_중복제거() {
        assertEquals(List.of(22, 80), ThreatConsoleService.포트정규화(List.of(22, 80, 22, 80), 100));
    }

    @Test
    @DisplayName("상한을 넘는 포트 목록은 잘린다")
    void 포트_상한() {
        List<Integer> 많음 = new ArrayList<>();
        for (int i = 1; i <= 300; i++) 많음.add(i);
        assertEquals(100, ThreatConsoleService.포트정규화(많음, 100).size());
    }

    @Test
    @DisplayName("null 목록과 null 원소에도 죽지 않는다")
    void 포트_null() {
        assertEquals(List.of(), ThreatConsoleService.포트정규화(null, 100));
        List<Integer> 섞임 = new ArrayList<>(Arrays.asList(22, null, 80));
        assertEquals(List.of(22, 80), ThreatConsoleService.포트정규화(섞임, 100));
    }

    @Test
    @DisplayName("입력 순서를 지킨다")
    void 포트_순서유지() {
        assertEquals(List.of(3389, 22, 445),
                ThreatConsoleService.포트정규화(List.of(3389, 22, 445), 100));
    }

    // ── 미탐지 포트 채우기 ───────────────────────────────────────────────

    @Test
    @DisplayName("공격이 없던 포트도 0 으로 돌려준다")
    void 미탐지_채움() {
        List<Map<String, Object>> items = new ArrayList<>();
        items.add(항목(22L, 500L));

        ThreatConsoleService.미탐지포트채우기(items, List.of(22, 80, 3389));

        assertEquals(3, items.size(), "조용한 포트가 화면에서 사라지면 '확인 안 됨' 과 구분되지 않는다");
        Map<Long, Map<String, Object>> 포트별 = new HashMap<>();
        for (Map<String, Object> m : items) 포트별.put(((Number) m.get("port")).longValue(), m);
        assertEquals(500L, 포트별.get(22L).get("events"));
        assertEquals(0L, 포트별.get(80L).get("events"));
        assertEquals(0L, 포트별.get(3389L).get("high_risk"));
        assertEquals(0L, 포트별.get(3389L).get("ip_count"));
        assertEquals(0L, 포트별.get(3389L).get("max_score"));
    }

    @Test
    @DisplayName("이미 집계된 포트를 두 번 넣지 않는다")
    void 미탐지_중복없음() {
        List<Map<String, Object>> items = new ArrayList<>();
        items.add(항목(22L, 500L));
        ThreatConsoleService.미탐지포트채우기(items, List.of(22));
        assertEquals(1, items.size());
    }

    @Test
    @DisplayName("채운 포트도 long 으로 통일한다")
    void 미탐지_타입() {
        List<Map<String, Object>> items = new ArrayList<>();
        ThreatConsoleService.미탐지포트채우기(items, List.of(8080));
        // 정렬과 비교가 Number 캐스팅에 기대므로 타입이 섞이면 조용히 깨진다.
        assertInstanceOf(Long.class, items.get(0).get("port"));
        assertInstanceOf(Long.class, items.get(0).get("events"));
    }

    // ── 정렬 ─────────────────────────────────────────────────────────────

    @Test
    @DisplayName("많이 맞은 포트가 먼저 온다")
    void 정렬_내림차순() {
        List<Map<String, Object>> items = new ArrayList<>(List.of(
                항목(80L, 10L), 항목(22L, 900L), 항목(445L, 50L)));

        ThreatConsoleService.이벤트많은순(items);

        assertEquals(22L, items.get(0).get("port"));
        assertEquals(445L, items.get(1).get("port"));
        assertEquals(80L, items.get(2).get("port"));
    }

    @Test
    @DisplayName("0 으로 채운 포트는 뒤로 간다")
    void 정렬_빈포트는_뒤로() {
        List<Map<String, Object>> items = new ArrayList<>();
        items.add(항목(22L, 5L));
        ThreatConsoleService.미탐지포트채우기(items, List.of(22, 80));
        ThreatConsoleService.이벤트많은순(items);

        assertEquals(22L, items.get(0).get("port"), "공격받은 포트가 먼저 보여야 한다");
    }

    @Test
    @DisplayName("빈 목록을 정렬해도 죽지 않는다")
    void 정렬_빈목록() {
        assertDoesNotThrow(() -> ThreatConsoleService.이벤트많은순(new ArrayList<>()));
    }

    private static Map<String, Object> 항목(long port, long events) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("port", port);
        m.put("events", events);
        return m;
    }
}
