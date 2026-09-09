package com.capstone.honeypot.service;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch._types.SortOrder;
import co.elastic.clients.elasticsearch._types.aggregations.Aggregate;
import co.elastic.clients.elasticsearch._types.aggregations.DateHistogramBucket;
import co.elastic.clients.elasticsearch._types.aggregations.HistogramBucket;
import co.elastic.clients.elasticsearch._types.aggregations.StringTermsBucket;
import co.elastic.clients.elasticsearch._types.query_dsl.Query;
import co.elastic.clients.elasticsearch.core.SearchResponse;
import co.elastic.clients.json.JsonData;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
@Slf4j
public class ThreatConsoleService {

    private final ElasticsearchClient es;
    private final ObjectMapper objectMapper = new ObjectMapper();

    // ── overview ─────────────────────────────────────────────────────────
    public Map<String, Object> overview() {
        String since = "now-24h";
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
        String window = (since == null || since.isBlank()) ? "now-24h" : since;
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

    // ── LLM recent ───────────────────────────────────────────────────────
    public Map<String, Object> llmRecent(String since, Integer size, String severity) {
        String window = (since == null || since.isBlank()) ? "now-7d" : since;
        int sz = size == null ? 30 : Math.min(Math.max(size, 1), 200);

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
        String window = (since == null || since.isBlank()) ? "now-7d" : since;
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
                "@timestamp", "src_ip", "dest_port", "honeypot",
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
        String window = (since == null || since.isBlank()) ? "now-7d" : since;
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
