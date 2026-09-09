package com.capstone.honeypot.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class InternalAttackLogRequest {
    private String username;
    private String attackType;
    private String payload;
    private String ipAddress;
}
