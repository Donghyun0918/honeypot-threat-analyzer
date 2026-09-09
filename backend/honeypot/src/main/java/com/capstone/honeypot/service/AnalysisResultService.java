package com.capstone.honeypot.service;

import com.capstone.honeypot.domain.AnalysisResult;
import com.capstone.honeypot.domain.AttackLog;
import com.capstone.honeypot.dto.AnalysisResultRequest;
import com.capstone.honeypot.dto.AnalysisResultResponse;
import com.capstone.honeypot.repository.AnalysisResultRepository;
import com.capstone.honeypot.repository.AttackLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AnalysisResultService {

    private final AnalysisResultRepository analysisResultRepository;
    private final AttackLogRepository attackLogRepository;

    public AnalysisResultResponse save(AnalysisResultRequest request) {
        AttackLog attackLog = attackLogRepository.findById(request.getAttackLogId())
                .orElseThrow(() -> new IllegalArgumentException("공격 로그가 없습니다. id=" + request.getAttackLogId()));

        AnalysisResult result = new AnalysisResult();
        result.setRiskScore(request.getRiskScore());
        result.setSeverity(request.getSeverity());
        result.setSummary(request.getSummary());
        result.setSolution(request.getSolution());
        result.setAttackLog(attackLog);

        AnalysisResult saved = analysisResultRepository.save(result);
        return new AnalysisResultResponse(saved);
    }

    public AnalysisResultResponse findByAttackLogId(Long attackLogId) {
        AnalysisResult result = analysisResultRepository.findByAttackLogId(attackLogId)
                .orElseThrow(() -> new IllegalArgumentException("분석 결과가 없습니다. attackLogId=" + attackLogId));

        return new AnalysisResultResponse(result);
    }
}