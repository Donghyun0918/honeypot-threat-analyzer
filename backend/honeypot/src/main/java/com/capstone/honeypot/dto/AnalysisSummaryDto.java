package com.capstone.honeypot.dto;

import com.capstone.honeypot.domain.AnalysisResult;
import lombok.Getter;

@Getter
public class AnalysisSummaryDto {

    private final Integer riskScore;
    private final String severity;
    private final String summary;
    private final String solution;

    public AnalysisSummaryDto(AnalysisResult analysisResult) {
        this.riskScore = analysisResult.getRiskScore();
        this.severity = analysisResult.getSeverity();
        this.summary = analysisResult.getSummary();
        this.solution = analysisResult.getSolution();
    }
}