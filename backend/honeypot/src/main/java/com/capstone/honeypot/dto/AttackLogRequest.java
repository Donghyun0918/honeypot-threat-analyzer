package com.capstone.honeypot.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AttackLogRequest {
    private String attackType;
    private String payload;
    private String ipAddress;
    private Long projectId;
}