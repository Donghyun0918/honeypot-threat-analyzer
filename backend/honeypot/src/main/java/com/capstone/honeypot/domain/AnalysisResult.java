package com.capstone.honeypot.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
public class AnalysisResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Integer riskScore;     // 0~100
    private String severity;       // LOW, MEDIUM, HIGH, CRITICAL

    @Column(columnDefinition = "TEXT")
    private String summary;        // 분석 요약

    @Column(columnDefinition = "TEXT")
    private String solution;       // 대응 방안

    @OneToOne
    @JoinColumn(name = "attack_log_id")
    private AttackLog attackLog;
}