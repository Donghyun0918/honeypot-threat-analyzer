package com.capstone.honeypot.service;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch._types.SortOrder;
import co.elastic.clients.elasticsearch._types.aggregations.Aggregate;
import co.elastic.clients.elasticsearch._types.aggregations.DateHistogramBucket;
import co.elastic.clients.elasticsearch._types.aggregations.HistogramBucket;
import co.elastic.clients.elasticsearch._types.FieldValue;
import co.elastic.clients.elasticsearch._types.aggregations.LongTermsBucket;
import co.elastic.clients.elasticsearch._types.aggregations.StringTermsBucket;
import co.elastic.clients.elasticsearch._types.query_dsl.Query;
import co.elastic.clients.elasticsearch.core.SearchResponse;
import co.elastic.clients.json.JsonData;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
@Slf4j
public class ThreatConsoleService {

    private final ElasticsearchClient es;
    private final ObjectMapper objectMapper = new ObjectMapper();

    // 집계 창. 라이브 운영에서는 기본값(24h / 7d)이 맞지만, 보관된 로그를
    // 적재해 시연할 때는 데이터가 몇 달 전이라 그대로 두면 화면이 전부 0 이
    // 된다. THREAT_CONSOLE_WINDOW_SHORT / _LONG 으로 덮어쓴다.
    @Value("${threat-console.window.short:now-24h}")
    private String 창짧음;

    @Value("${threat-console.window.long:now-7d}")
    private String 창김;

    // ── overview ─────────────────────────────────────────────────────────
    public Map<String, Object> overview(String since) {
        since = 창(since, 창짧음);
        long totalEvents  = safeCount("logstash-*",     timeGteQuery(since));
        long totalAttacks = safeCount("ml-analysis-*",  boolFilter(timeGteQuery(since), termBoolQuery("ml_is_attack", true)));
        long highRisk     = safeCount("ml-analysis-*",  boolFilter(timeGteQuery(since), gteNumberQuery("mitre_score", 70)));
        long llmAnalyzed  = safeCount("llm-analysis-*", timeGteQuery(since));

        Map<String, Object> m = new LinkedHashMap<>();
        m.put("since", since);
        m.put("total_events", totalEvents);
        m.put("total_attacks", totalAttacks);
        m.put("high_risk", highRisk);
        m.put("llm_analyzed", llmAnalyzed);
        return m;
    }

    // ── ML stats ─────────────────────────────────────────────────────────
    public Map<String, Object> mlStats(String since) {
        String window = 창(since, 창짧음);
        try {
            SearchResponse<Void> r = es.search(s -> s
                    .index("ml-analysis-*")
                    .size(0)
                    .trackTotalHits(t -> t.enabled(true))
                    .ignoreUnavailable(true)
                    .query(timeGteQuery(window))
                    .aggregations("labels",     a -> a.terms(t -> t.field("ml_label.keyword").size(10)))
                    .aggregations("honeypots",  a -> a.terms(t -> t.field("honeypot.keyword").size(15)))
                    .aggregations("by_hour",    a -> a.dateHistogram(d -> d.field("@timestamp").fixedInterval(ti -> ti.time("1h"))))
                    .aggregations("score_dist", a -> a.histogram(h -> h.field("mitre_score").interval(10.0).minDocCount(0)))
                    .aggregations("model_used", a -> a.terms(t -> t.field("model_used.keyword").size(5))),
                    Void.class);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("labels",     stringTermsBuckets(r, "labels"));
            result.put("honeypots",  stringTermsBuckets(r, "honeypots"));
            result.put("by_hour",    dateHistogramBuckets(r, "by_hour"));
            result.put("score_dist", numericHistogramBuckets(r, "score_dist", "score"));
            result.put("model_used", stringTermsBuckets(r, "model_used"));
            return result;
        } catch (Exception e) {
            log.warn("mlStats failed: {}", e.toString());
            Map<String, Object> empty = new LinkedHashMap<>();
            empty.put("labels", List.of());
            empty.put("honeypots", List.of());
            empty.put("by_hour", List.of());
            empty.put("score_dist", List.of());
            empty.put("model_used", List.of());
            return empty;
        }
    }

    // ── 이미 만들어둔 해설 조회 ──────────────────────────────────────────
    /**
     * 사건 하나에 대해 <b>이미 색인된</b> 한국어 해설을 돌려준다. 없으면 빈 Map.
     *
     * <p>llm-analyzer 는 패턴당 한 번만 모델을 부르지만 결과는 <b>사건마다</b>
     * 문서로 남긴다(12-5). 그래서 여기서는 그룹 키를 다시 계산할 필요 없이
     * 사건 id 로 바로 찾으면 된다 — 임시 포트 접기 같은 규칙을 Java 에 한 번 더
     * 옮겨 적으면 두 구현이 어긋나는 순간 조용히 틀린 해설을 보여주게 된다.
     *
     * <p>이게 온디맨드 추론 정책의 핵심이다. 고위험 사건은 대부분 이미 해설이
     * 있으므로 <b>추론 없이 0초에</b> 답이 나온다. 모델을 부르는 것은 해설이
     * 아직 없는 사건뿐이다.
     */
    public Map<String, Object> llmExplain(String sourceDocId) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (sourceDocId == null || sourceDocId.isBlank()) {
            out.put("found", false);
            return out;
        }
        try {
            SearchResponse<Map> r = es.search(s -> s
                    .index("llm-analysis-*")
                    .size(1)
                    .ignoreUnavailable(true)
                    .query(q -> q.term(t -> t.field("source_doc_id").value(sourceDocId)))
                    .source(src -> src.filter(f -> f.includes(List.of(
                            "summary_ko", "solution_ko", "severity", "risk_score",
                            "ttp_inferred", "llm_model", "llm_group_key",
                            "llm_group_reused", "analyzed_at")))),
                    Map.class);

            var hits = r.hits().hits();
            if (hits.isEmpty() || hits.get(0).source() == null) {
                out.put("found", false);
                return out;
            }
            out.put("found", true);
            out.putAll((Map<String, Object>) hits.get(0).source());
            return out;
        } catch (Exception e) {
            log.warn("llmExplain failed: {}", e.toString());
            out.put("found", false);
            return out;
        }
    }

    // ── 자산 노출 대조 ───────────────────────────────────────────────────
    /**
     * 내가 가진 포트들이 <b>실제로 얼마나 얻어맞고 있는지</b> 돌려준다.
     *
     * <p>허니팟 데이터의 약점은 그것이 "남의 얘기" 라는 점이다 — 우리 대역을
     * 노리는 공격이지 우리가 뚫렸다는 뜻이 아니다. 값이 서려면 고객 자산과
     * 연결해야 한다: <i>"445 를 노린 공격이 40,487건인데, 당신 서버 3대에
     * 445 가 열려 있다"</i>.
     *
     * <p>파이프라인은 이미 {@code dest_port} 를 뽑고 있으므로 연결에 필요한 것은
     * 포트 목록뿐이다. ML 도 LLM 도 쓰지 않는다.
     *
     * @param ports 조회할 포트. 비어 있으면 빈 결과를 돌려준다(전체를 훑지 않는다).
     */
    public Map<String, Object> exposure(String since, List<Integer> ports) {
        String window = 창(since, 창김);
        Map<String, Object> out = new LinkedHashMap<>();

        if (ports == null || ports.isEmpty()) {
            out.put("items", List.of());
            out.put("checked", 0);
            return out;
        }
        // 한 번에 너무 많은 포트를 받으면 집계가 무거워진다. 자산 목록 규모로는
        // 넉넉한 상한이다.
        List<Integer> 대상 = 포트정규화(ports, 100);

        try {
            List<FieldValue> 값들 = 대상.stream().map(FieldValue::of).toList();
            SearchResponse<Void> r = es.search(s -> s
                    .index("ml-analysis-*")
                    .size(0)
                    .trackTotalHits(t -> t.enabled(true))
                    .ignoreUnavailable(true)
                    .query(q -> q.bool(b -> b
                            .filter(timeGteQuery(window))
                            .filter(f -> f.terms(t -> t.field("dest_port")
                                    .terms(tt -> tt.value(값들))))))
                    .aggregations("by_port", a -> a
                            .terms(t -> t.field("dest_port").size(대상.size()))
                            .aggregations("high", sub -> sub.filter(f -> f
                                    .range(rg -> rg.field("mitre_score").gte(JsonData.of(70)))))
                            .aggregations("top_label", sub -> sub.terms(t -> t.field("ml_label.keyword").size(1)))
                            .aggregations("max_score", sub -> sub.max(m -> m.field("mitre_score")))
                            // ml-analysis-* 의 src_ip 는 text+keyword 다(인덱스
                            // 템플릿은 생성 시점에만 적용되므로 먼저 만들어진
                            // 인덱스는 동적 매핑을 따랐다). 원본 필드로 집계하면
                            // "Fielddata is disabled" 로 전량 실패한다.
                            .aggregations("ips", sub -> sub.cardinality(c -> c.field("src_ip.keyword")))),
                    Void.class);

            List<Map<String, Object>> items = new ArrayList<>();
            Aggregate agg = r.aggregations().get("by_port");
            if (agg != null && agg.isLterms()) {
                for (LongTermsBucket b : agg.lterms().buckets().array()) {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("port", b.key());
                    m.put("events", b.docCount());

                    Aggregate high = b.aggregations().get("high");
                    m.put("high_risk", high != null && high.isFilter() ? high.filter().docCount() : 0);

                    Aggregate ips = b.aggregations().get("ips");
                    m.put("ip_count", ips != null && ips.isCardinality() ? ips.cardinality().value() : 0);

                    Aggregate max = b.aggregations().get("max_score");
                    m.put("max_score", max != null && max.isMax() && !Double.isInfinite(max.max().value())
                            ? (long) max.max().value() : 0);

                    Aggregate lbl = b.aggregations().get("top_label");
                    if (lbl != null && lbl.isSterms()) {
                        lbl.sterms().buckets().array().stream().findFirst()
                                .ifPresent(x -> m.put("top_label", x.key().stringValue()));
                    }
                    items.add(m);
                }
            }
            미탐지포트채우기(items, 대상);
            이벤트많은순(items);

            out.put("items", items);
            out.put("checked", 대상.size());
            out.put("matched_events", r.hits().total() == null ? 0 : r.hits().total().value());
            return out;
        } catch (Exception e) {
            log.warn("exposure failed: {}", e.toString());
            out.put("items", List.of());
            out.put("checked", 대상.size());
            out.put("matched_events", 0);
            return out;
        }
    }

    // ── LLM patterns ─────────────────────────────────────────────────────
    /**
     * 해설을 <b>공격 패턴 단위</b>로 접어서 돌려준다.
     *
     * <p>llm-analyzer 가 패턴당 한 번만 해설하도록 바뀌면서(실측: 고위험
     * 45,075건이 74개 패턴, 상위 2개가 89.8%) 같은 문장을 가진 문서가 수백~수만
     * 건씩 생긴다. {@link #llmRecent} 를 그대로 쓰면 화면에 <b>똑같은 문단이 324줄</b>
     * 나온다 — 파이프라인은 패턴 단위로 갔는데 화면만 건별로 남은 것이다.
     *
     * <p>여기서 접으면 반복이 사라질 뿐 아니라 이 프로젝트가 측정으로 찾아낸 사실
     * ("4만 건이 실은 수십 개 패턴")이 화면에 그대로 드러난다.
     *
     * <p>패턴 키가 없는 문서(변경 전에 건별로 해설된 것)는 버리지 않고
     * {@code (건별 해설)} 버킷으로 모은다 — 조용히 사라지면 합계가 안 맞는다.
     */
    public Map<String, Object> llmPatterns(String since, Integer size, String severity) {
        String window = 창(since, 창김);
        int sz = 크기(size, 20, 100);

        List<Query> filters = new ArrayList<>();
        filters.add(timeGteQuery(window));
        if (severity != null && !severity.isBlank()) {
            filters.add(Query.of(q -> q.term(t -> t.field("severity").value(severity))));
        }

        try {
            SearchResponse<Void> r = es.search(s -> s
                    .index("llm-analysis-*")
                    .size(0)
                    .trackTotalHits(t -> t.enabled(true))
                    .ignoreUnavailable(true)
                    .query(q -> q.bool(b -> b.filter(filters)))
                    .aggregations("patterns", a -> a
                            .terms(t -> t.field("llm_group_key").size(sz).missing("(건별 해설)"))
                            // 대표 1건에서 해설 문구를 가져온다. 같은 패턴이면
                            // 어느 건을 뽑아도 문구가 같다.
                            .aggregations("sample", sub -> sub.topHits(th -> th
                                    .size(1)
                                    .sort(so -> so.field(f -> f.field("@timestamp").order(SortOrder.Desc)))
                                    .source(src -> src.filter(f -> f.includes(List.of(
                                            "summary_ko", "solution_ko", "severity", "risk_score",
                                            "mitre_score", "ttp_inferred", "honeypot", "ml_label",
                                            "dest_port", "llm_model"))))))
                            // 같은 패턴을 두드린 공격자가 몇이나 되는지. 패턴
                            // 하나가 IP 한 개면 표적, 수천 개면 무차별 스캔이다.
                            .aggregations("ips", sub -> sub.cardinality(c -> c.field("src_ip")))
                            .aggregations("latest", sub -> sub.max(m -> m.field("@timestamp")))),
                    Void.class);

            List<Map<String, Object>> items = new ArrayList<>();
            Aggregate agg = r.aggregations().get("patterns");
            if (agg != null && agg.isSterms()) {
                for (StringTermsBucket b : agg.sterms().buckets().array()) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("group_key", b.key().stringValue());
                    item.put("count", b.docCount());

                    Aggregate ips = b.aggregations().get("ips");
                    item.put("ip_count", ips != null && ips.isCardinality() ? ips.cardinality().value() : 0);

                    Aggregate latest = b.aggregations().get("latest");
                    if (latest != null && latest.isMax() && latest.max().valueAsString() != null) {
                        item.put("latest", latest.max().valueAsString());
                    }

                    // top_hits 의 _source 는 JsonData 다. convertValue 로 넘기면
                    // 조용히 빈 Map 이 되어 해설 문구가 통째로 사라진다 —
                    // 화면에는 "분석 결과 없음" 이 아니라 빈 칸으로 보인다.
                    Aggregate sample = b.aggregations().get("sample");
                    if (sample != null && sample.isTopHits()) {
                        sample.topHits().hits().hits().stream().findFirst().ifPresent(h -> {
                            if (h.source() != null) {
                                item.putAll(h.source().to(Map.class));
                            }
                        });
                    }
                    items.add(item);
                }
            }

            Map<String, Object> m = new LinkedHashMap<>();
            m.put("items", items);
            m.put("pattern_count", items.size());
            m.put("event_total", r.hits().total() == null ? 0 : r.hits().total().value());
            return m;
        } catch (Exception e) {
            log.warn("llmPatterns failed: {}", e.toString());
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("items", List.of());
            m.put("pattern_count", 0);
            m.put("event_total", 0);
            return m;
        }
    }

    // ── LLM recent ───────────────────────────────────────────────────────
    public Map<String, Object> llmRecent(String since, Integer size, String severity) {
        String window = 창(since, 창김);
        int sz = 크기(size, 30, 200);

        List<Query> filters = new ArrayList<>();
        filters.add(timeGteQuery(window));
        if (severity != null && !severity.isBlank()) {
            filters.add(Query.of(q -> q.term(t -> t.field("severity").value(severity))));
        }

        try {
            SearchResponse<Map> r = es.search(s -> s
                    .index("llm-analysis-*")
                    .size(sz)
                    .trackTotalHits(t -> t.enabled(true))
                    .ignoreUnavailable(true)
                    .sort(so -> so.field(f -> f.field("@timestamp").order(SortOrder.Desc)))
                    .query(q -> q.bool(b -> b.filter(filters)))
                    .source(src -> src.filter(f -> f.includes(List.of(
                            "@timestamp", "src_ip", "honeypot", "ml_label",
                            "mitre_score", "risk_score", "severity",
                            "summary_ko", "solution_ko", "ttp_inferred")))),
                    Map.class);

            List<Map<String, Object>> items = new ArrayList<>();
            r.hits().hits().forEach(h -> {
                if (h.source() != null) items.add((Map<String, Object>) h.source());
            });
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("items", items);
            m.put("count", items.size());
            return m;
        } catch (Exception e) {
            log.warn("llmRecent failed: {}", e.toString());
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("items", List.of());
            m.put("count", 0);
            return m;
        }
    }

    // ── LLM stats ────────────────────────────────────────────────────────
    public Map<String, Object> llmStats(String since) {
        String window = 창(since, 창김);
        try {
            SearchResponse<Void> r = es.search(s -> s
                    .index("llm-analysis-*")
                    .size(0)
                    .trackTotalHits(t -> t.enabled(true))
                    .ignoreUnavailable(true)
                    .query(timeGteQuery(window))
                    .aggregations("severity",  a -> a.terms(t -> t.field("severity").size(4)))
                    .aggregations("honeypots", a -> a.terms(t -> t.field("honeypot.keyword").size(10)))
                    .aggregations("risk_dist", a -> a.histogram(h -> h.field("risk_score").interval(1.0).minDocCount(0))),
                    Void.class);
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("severity",  stringTermsBuckets(r, "severity"));
            result.put("honeypots", stringTermsBuckets(r, "honeypots"));
            result.put("risk_dist", numericHistogramBuckets(r, "risk_dist", "score"));
            return result;
        } catch (Exception e) {
            log.warn("llmStats failed: {}", e.toString());
            Map<String, Object> empty = new LinkedHashMap<>();
            empty.put("severity", List.of());
            empty.put("honeypots", List.of());
            empty.put("risk_dist", List.of());
            return empty;
        }
    }

    // ── Export: ML / LLM as raw rows (controller formats CSV/JSON) ───────
    public List<Map<String, Object>> exportMl(String since) {
        return rawExport("ml-analysis-*", since, 10000, List.of(
                // source_doc_id 는 llm-analysis-* 문서의 _id 와 같다. 이걸 내보내야
                // 화면이 "이 사건에 이미 해설이 있는가" 를 키 계산 없이 바로 묻는다.
                "@timestamp", "source_doc_id", "src_ip", "dest_port", "honeypot",
                "ml_label", "ml_is_attack", "ml_multi_conf",
                "mitre_score", "mitre_technique", "model_used", "model_version"));
    }

    public List<Map<String, Object>> exportLlm(String since) {
        return rawExport("llm-analysis-*", since, 5000, List.of(
                "@timestamp", "src_ip", "honeypot", "ml_label",
                "mitre_score", "risk_score", "severity",
                "summary_ko", "solution_ko", "ttp_inferred"));
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> rawExport(String index, String since, int size, List<String> sourceFields) {
        String window = 창(since, 창김);
        try {
            SearchResponse<Map> r = es.search(s -> s
                    .index(index)
                    .size(size)
                    .trackTotalHits(t -> t.enabled(true))
                    .ignoreUnavailable(true)
                    .sort(so -> so.field(f -> f.field("@timestamp").order(SortOrder.Desc)))
                    .query(timeGteQuery(window))
                    .source(src -> src.filter(f -> f.includes(sourceFields))),
                    Map.class);
            List<Map<String, Object>> rows = new ArrayList<>();
            r.hits().hits().forEach(h -> {
                if (h.source() != null) rows.add((Map<String, Object>) h.source());
            });
            return rows;
        } catch (Exception e) {
            log.warn("rawExport failed on {}: {}", index, e.toString());
            return List.of();
        }
    }

    // ── helper: count docs only (size=0) ─────────────────────────────────
    private long safeCount(String index, Query query) {
        try {
            SearchResponse<Void> r = es.search(s -> s
                    .index(index)
                    .size(0)
                    .trackTotalHits(t -> t.enabled(true))
                    .ignoreUnavailable(true)
                    .query(query),
                    Void.class);
            return r.hits().total() == null ? 0L : r.hits().total().value();
        } catch (Exception e) {
            log.warn("ES count failed on {}: {}", index, e.toString());
            return 0L;
        }
    }

    // ── query builders ───────────────────────────────────────────────────
    // ── 순수 헬퍼 ────────────────────────────────────────────────────────
    // ES 를 타지 않는 계산만 모아둔다. 같은 식이 메서드마다 인라인으로 반복되고
    // 있었고(창 기본값 5곳, 크기 제한 2곳), 그런 중복은 한 곳만 고치게 된다 —
    // 폼보드 SVG 가 87.6 을 하드코딩하고 있던 것과 같은 종류다(§12).
    // 여기로 모으면 테스트도 붙는다.

    /** {@code since} 가 비었으면 기본 창을 쓴다. */
    static String 창(String since, String 기본) {
        return (since == null || since.isBlank()) ? 기본 : since;
    }

    /**
     * 요청한 개수를 허용 범위로 자른다.
     *
     * <p>상한이 필요한 이유: 화면이 {@code size=100000} 을 보내면 ES 집계가
     * 그대로 무거워진다. 하한이 필요한 이유: 0 이나 음수를 그대로 넘기면
     * terms 집계가 오류를 낸다 — 사용자 입력 하나로 조회가 깨진다.
     */
    static int 크기(Integer size, int 기본, int 최대) {
        if (size == null) return 기본;
        return Math.min(Math.max(size, 1), 최대);
    }

    /** 자산 포트 목록을 집계에 쓸 수 있게 정리한다(중복 제거 + 상한). */
    static List<Integer> 포트정규화(List<Integer> ports, int 상한) {
        if (ports == null) return List.of();
        return ports.stream()
                .filter(Objects::nonNull)
                .distinct()
                .limit(상한)
                .toList();
    }

    /**
     * 공격이 한 건도 없던 포트를 0 으로 채운다.
     *
     * <p><b>"안 맞고 있다" 도 답이다.</b> 집계 결과에만 의존하면 조용한 포트가
     * 화면에서 사라지는데, 사용자는 그걸 "아직 확인 안 됨" 과 구분할 수 없다.
     */
    static void 미탐지포트채우기(List<Map<String, Object>> items, List<Integer> 대상) {
        Set<Long> 본것 = new HashSet<>();
        for (Map<String, Object> m : items) {
            본것.add(((Number) m.get("port")).longValue());
        }
        for (Integer port : 대상) {
            if (port == null || 본것.contains(port.longValue())) continue;
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("port", port.longValue());
            m.put("events", 0L);
            m.put("high_risk", 0L);
            m.put("ip_count", 0L);
            m.put("max_score", 0L);
            items.add(m);
        }
    }

    /** 많이 맞은 포트부터. 0 으로 채운 포트는 자연히 뒤로 간다. */
    static void 이벤트많은순(List<Map<String, Object>> items) {
        items.sort((x, y) -> Long.compare(
                ((Number) y.get("events")).longValue(),
                ((Number) x.get("events")).longValue()));
    }

    private Query timeGteQuery(String since) {
        return Query.of(q -> q.range(r -> r.field("@timestamp").gte(JsonData.of(since))));
    }

    private Query gteNumberQuery(String field, long value) {
        return Query.of(q -> q.range(r -> r.field(field).gte(JsonData.of(value))));
    }

    private Query termBoolQuery(String field, boolean value) {
        return Query.of(q -> q.term(t -> t.field(field).value(value)));
    }

    private Query boolFilter(Query... filters) {
        return Query.of(q -> q.bool(b -> {
            for (Query f : filters) b.filter(f);
            return b;
        }));
    }

    // ── aggregation extractors ───────────────────────────────────────────
    private List<Map<String, Object>> stringTermsBuckets(SearchResponse<?> r, String name) {
        List<Map<String, Object>> out = new ArrayList<>();
        Aggregate agg = r.aggregations().get(name);
        if (agg == null) return out;
        if (agg.isSterms()) {
            for (StringTermsBucket b : agg.sterms().buckets().array()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("key", b.key().stringValue());
                m.put("count", b.docCount());
                out.add(m);
            }
        } else if (agg.isLterms()) {
            agg.lterms().buckets().array().forEach(b -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("key", b.key());
                m.put("count", b.docCount());
                out.add(m);
            });
        }
        return out;
    }

    private List<Map<String, Object>> dateHistogramBuckets(SearchResponse<?> r, String name) {
        List<Map<String, Object>> out = new ArrayList<>();
        Aggregate agg = r.aggregations().get(name);
        if (agg == null || !agg.isDateHistogram()) return out;
        for (DateHistogramBucket b : agg.dateHistogram().buckets().array()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ts", b.keyAsString());
            m.put("count", b.docCount());
            out.add(m);
        }
        return out;
    }

    private List<Map<String, Object>> numericHistogramBuckets(SearchResponse<?> r, String name, String keyName) {
        List<Map<String, Object>> out = new ArrayList<>();
        Aggregate agg = r.aggregations().get(name);
        if (agg == null || !agg.isHistogram()) return out;
        for (HistogramBucket b : agg.histogram().buckets().array()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put(keyName, b.key());
            m.put("count", b.docCount());
            out.add(m);
        }
        return out;
    }
}
