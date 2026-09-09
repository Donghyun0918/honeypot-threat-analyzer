package com.capstone.honeypot.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AnalysisResultRequest {
    private Integer riskScore;
    private String severity;
    private String summary;
    private String solution;
    private Long attackLogId;
}