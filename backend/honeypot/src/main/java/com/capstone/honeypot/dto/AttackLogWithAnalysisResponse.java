package com.capstone.honeypot.dto;

import com.capstone.honeypot.domain.AttackLog;
import com.capstone.honeypot.domain.AnalysisResult;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
public class AttackLogWithAnalysisResponse {

    private final Long attackLogId;
    private final String attackType;
    private final String payload;
    private final String ipAddress;
    private final LocalDateTime createdAt;
    private final AnalysisSummaryDto analysis;

    public AttackLogWithAnalysisResponse(AttackLog attackLog, AnalysisResult analysisResult) {
        this.attackLogId = attackLog.getId();
        this.attackType = attackLog.getAttackType();
        this.payload = attackLog.getPayload();
        this.ipAddress = attackLog.getIpAddress();
        this.createdAt = attackLog.getCreatedAt();
        this.analysis = analysisResult != null ? new AnalysisSummaryDto(analysisResult) : null;
    }
}