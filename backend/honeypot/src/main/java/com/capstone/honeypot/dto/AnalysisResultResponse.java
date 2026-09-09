package com.capstone.honeypot.dto;

import com.capstone.honeypot.domain.AnalysisResult;
import lombok.Getter;

@Getter
public class AnalysisResultResponse {

    private Long id;
    private Integer riskScore;
    private String severity;
    private String summary;
    private String solution;
    private Long attackLogId;

    public AnalysisResultResponse(AnalysisResult result) {
        this.id = result.getId();
        this.riskScore = result.getRiskScore();
        this.severity = result.getSeverity();
        this.summary = result.getSummary();
        this.solution = result.getSolution();
        this.attackLogId = result.getAttackLog().getId();
    }
}