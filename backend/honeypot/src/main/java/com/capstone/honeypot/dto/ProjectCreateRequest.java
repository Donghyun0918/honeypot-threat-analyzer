package com.capstone.honeypot.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ProjectCreateRequest {
    private String name;
    private String description;
}