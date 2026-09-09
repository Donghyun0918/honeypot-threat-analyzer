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

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class ThreatConsoleController {

    private final ThreatConsoleService service;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @GetMapping("/api/overview")
    public Map<String, Object> overview() {
        return service.overview();
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
