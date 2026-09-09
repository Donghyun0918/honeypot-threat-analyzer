package com.capstone.honeypot.service;

import com.capstone.honeypot.domain.AnalysisResult;
import com.capstone.honeypot.domain.AttackLog;
import com.capstone.honeypot.domain.Project;
import com.capstone.honeypot.dto.AttackLogRequest;
import com.capstone.honeypot.dto.AttackLogResponse;
import com.capstone.honeypot.dto.AttackLogWithAnalysisResponse;
import com.capstone.honeypot.repository.AnalysisResultRepository;
import com.capstone.honeypot.repository.AttackLogRepository;
import com.capstone.honeypot.repository.ProjectRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AttackLogService {

    private final AttackLogRepository attackLogRepository;
    private final ProjectRepository projectRepository;
    private final AnalysisService analysisService;
    private final AnalysisResultRepository analysisResultRepository;

    public AttackLogResponse save(AttackLogRequest request) {

        Project project = projectRepository.findById(request.getProjectId())
                .orElseThrow(() -> new IllegalArgumentException("프로젝트가 없습니다. id=" + request.getProjectId()));

        AttackLog log = new AttackLog();
        log.setAttackType(request.getAttackType());
        log.setPayload(request.getPayload());
        log.setIpAddress(request.getIpAddress());
        log.setCreatedAt(LocalDateTime.now());
        log.setProject(project);

        AttackLog savedLog = attackLogRepository.save(log);

        // 분석은 부가 기능이다. 외부 서비스가 없거나 실패하면 분석 결과를
        // 남기지 않는다 — 추측한 점수를 저장하면 진짜 분석과 구분되지 않는다.
        analysisService.analyze(
                savedLog.getAttackType(),
                savedLog.getPayload(),
                savedLog.getIpAddress()
        ).ifPresent(result -> {
            AnalysisResult analysisResult = new AnalysisResult();
            analysisResult.setAttackLog(savedLog);
            analysisResult.setRiskScore(asInt(result.get("riskScore")));
            analysisResult.setSeverity(asText(result.get("severity")));
            analysisResult.setSummary(asText(result.get("summary")));
            analysisResult.setSolution(asText(result.get("solution")));
            analysisResultRepository.save(analysisResult);
        });

        return new AttackLogResponse(savedLog);
    }

    public List<AttackLogResponse> findByProject(Long projectId) {
        return attackLogRepository.findByProjectId(projectId)
                .stream()
                .map(AttackLogResponse::new)
                .toList();
    }

    public List<AttackLogWithAnalysisResponse> findLogsWithAnalysisByProject(Long projectId) {
        List<AttackLog> logs = attackLogRepository.findByProjectId(projectId);
        if (logs.isEmpty()) {
            return List.of();
        }

        // 로그마다 분석을 따로 조회하면 N+1 이다(로그 1,000건이면 쿼리 1,001번).
        // 한 번에 받아 메모리에서 짝지으면 쿼리는 항상 2번이다.
        Map<Long, AnalysisResult> 분석 = analysisResultRepository
                .findByAttackLogIdIn(logs.stream().map(AttackLog::getId).toList())
                .stream()
                .collect(Collectors.toMap(r -> r.getAttackLog().getId(), r -> r, (a, b) -> a));

        return logs.stream()
                .map(log -> new AttackLogWithAnalysisResponse(log, 분석.get(log.getId())))
                .toList();
    }

    /** 외부 JSON 은 숫자를 Integer/Double 어느 쪽으로도 준다 — 캐스팅하면 깨진다. */
    private static Integer asInt(Object v) {
        return (v instanceof Number n) ? n.intValue() : null;
    }

    private static String asText(Object v) {
        return v == null ? null : v.toString();
    }
}