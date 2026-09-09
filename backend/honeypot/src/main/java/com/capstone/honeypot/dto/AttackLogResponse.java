package com.capstone.honeypot.dto;

import com.capstone.honeypot.domain.AttackLog;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
public class AttackLogResponse {

    private Long id;
    private String attackType;
    private String payload;
    private String ipAddress;
    private LocalDateTime createdAt;

    public AttackLogResponse(AttackLog log) {
        this.id = log.getId();
        this.attackType = log.getAttackType();
        this.payload = log.getPayload();
        this.ipAddress = log.getIpAddress();
        this.createdAt = log.getCreatedAt();
    }
}