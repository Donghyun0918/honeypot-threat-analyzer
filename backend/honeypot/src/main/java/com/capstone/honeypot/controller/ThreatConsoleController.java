package com.capstone.honeypot.controller;

import com.capstone.honeypot.service.ThreatConsoleService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class ThreatConsoleController {

    private final ThreatConsoleService service;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @GetMapping("/api/overview")
    public Map<String, Object> overview(@RequestParam(required = false) String since) {
        return service.overview(since);
    }

    @GetMapping("/api/ml-stats")
    public Map<String, Object> mlStats(@RequestParam(required = false) String since) {
        return service.mlStats(since);
    }

    @GetMapping("/api/llm-recent")
    public Map<String, Object> llmRecent(
            @RequestParam(required = false) String since,
            @RequestParam(required = false) Integer size,
            @RequestParam(required = false) String severity) {
        return service.llmRecent(since, size, severity);
    }

    /**
     * 해설을 공격 패턴 단위로 접어서 준다.
     *
     * <p>llm-analyzer 가 패턴당 한 번만 해설하므로 건별 목록
     * ({@code /api/llm-recent})은 같은 문단을 수백 줄 반복한다. 화면은 이쪽을 쓴다.
     */
    @GetMapping("/api/llm-patterns")
    public Map<String, Object> llmPatterns(
            @RequestParam(required = false) String since,
            @RequestParam(required = false) Integer size,
            @RequestParam(required = false) String severity) {
        return service.llmPatterns(since, size, severity);
    }

    /**
     * 내 자산의 포트가 실제로 얼마나 공격받고 있는지.
     *
     * <p>{@code ?ports=445,22,3306} 형태로 받는다. 허니팟 데이터를 "남의 얘기"
     * 에서 "당신 얘기" 로 바꾸는 연결이다.
     */
    @GetMapping("/api/exposure")
    public Map<String, Object> exposure(
            @RequestParam(required = false) String since,
            @RequestParam(required = false) String ports) {
        List<Integer> 목록 = new ArrayList<>();
        if (ports != null) {
            for (String tok : ports.split("[,\\s]+")) {
                if (tok.isBlank()) continue;
                try {
                    int v = Integer.parseInt(tok.trim());
                    if (v >= 0 && v <= 65535) 목록.add(v);
                } catch (NumberFormatException ignored) {
                    // 숫자가 아닌 토큰은 조용히 버린다 — 자산 목록에 주석이나
                    // 호스트명이 섞여 들어오는 것이 정상이다.
                }
            }
        }
        return service.exposure(since, 목록);
    }

    /**
     * 사건 하나의 이미 만들어둔 해설. 없으면 {@code found=false}.
     *
     * <p>화면은 사건을 고르는 즉시 이걸 묻고, 있으면 추론 없이 바로 보여준다.
     */
    @GetMapping("/api/llm-explain")
    public Map<String, Object> llmExplain(@RequestParam(required = false) String id) {
        return service.llmExplain(id);
    }

    @GetMapping("/api/llm-stats")
    public Map<String, Object> llmStats(@RequestParam(required = false) String since) {
        return service.llmStats(since);
    }

    @GetMapping("/api/export/ml")
    public ResponseEntity<byte[]> exportMl(
            @RequestParam(required = false) String since,
            @RequestParam(required = false, defaultValue = "csv") String format) {
        String window = (since == null || since.isBlank()) ? "now-7d" : since;
        List<Map<String, Object>> rows = service.exportMl(window);
        List<String> cols = List.of("@timestamp", "ml_label", "ml_is_attack", "ml_multi_conf",
                "mitre_score", "mitre_technique", "src_ip", "dest_port",
                "honeypot", "model_used", "model_version");
        return buildExport(rows, cols, "ml-analysis", window, format, false);
    }

    @GetMapping("/api/export/llm")
    public ResponseEntity<byte[]> exportLlm(
            @RequestParam(required = false) String since,
            @RequestParam(required = false, defaultValue = "csv") String format) {
        String window = (since == null || since.isBlank()) ? "now-7d" : since;
        List<Map<String, Object>> rows = service.exportLlm(window);
        List<String> cols = List.of("@timestamp", "severity", "risk_score", "mitre_score",
                "src_ip", "honeypot", "ml_label",
                "summary_ko", "solution_ko", "ttp_inferred");
        return buildExport(rows, cols, "llm-analysis", window, format, true);
    }

    // ── helpers ──────────────────────────────────────────────────────────
    @SuppressWarnings("unchecked")
    private ResponseEntity<byte[]> buildExport(List<Map<String, Object>> rows,
                                                List<String> cols,
                                                String baseName,
                                                String since,
                                                String format,
                                                boolean ttpJoinPipe) {
        String slug = since.replace("-", "");
        if ("json".equalsIgnoreCase(format)) {
            StringBuilder sb = new StringBuilder("[\n");
            boolean first = true;
            for (Map<String, Object> row : rows) {
                if (!first) sb.append(",\n");
                try {
                    sb.append(objectMapper.writeValueAsString(row));
                } catch (JsonProcessingException e) {
                    sb.append("{}");
                }
                first = false;
            }
            sb.append("\n]");
            byte[] body = sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            HttpHeaders h = new HttpHeaders();
            h.setContentType(MediaType.APPLICATION_JSON);
            h.set(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + baseName + "-" + slug + ".json\"");
            return ResponseEntity.ok().headers(h).body(body);
        }

        // CSV with BOM for Korean Excel
        StringBuilder csv = new StringBuilder("﻿");
        csv.append(String.join(",", cols)).append("\n");
        for (Map<String, Object> row : rows) {
            for (int i = 0; i < cols.size(); i++) {
                String col = cols.get(i);
                Object v = row.get(col);
                String cell;
                if ("ttp_inferred".equals(col) && v instanceof List<?> list) {
                    cell = list.stream().map(String::valueOf).collect(Collectors.joining(";"));
                } else if (v == null) {
                    cell = "";
                } else {
                    cell = String.valueOf(v);
                }
                csv.append(csvEscape(cell));
                if (i < cols.size() - 1) csv.append(",");
            }
            csv.append("\n");
        }
        byte[] body = csv.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        HttpHeaders h = new HttpHeaders();
        h.setContentType(MediaType.parseMediaType("text/csv; charset=utf-8"));
        h.set(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + baseName + "-" + slug + ".csv\"");
        return ResponseEntity.ok().headers(h).body(body);
    }

    private static String csvEscape(String s) {
        if (s == null) return "";
        boolean needsQuote = s.contains(",") || s.contains("\"") || s.contains("\n") || s.contains("\r");
        String escaped = s.replace("\"", "\"\"");
        return needsQuote ? "\"" + escaped + "\"" : escaped;
    }
}
