package com.capstone.honeypot.dto;

import com.capstone.honeypot.domain.Project;
import lombok.Getter;

@Getter
public class ProjectResponse {

    private final Long id;
    private final String name;
    private final String description;
    private final Long userId;
    private final String userEmail;

    public ProjectResponse(Project project) {
        this.id = project.getId();
        this.name = project.getName();
        this.description = project.getDescription();
        this.userId = project.getUser().getId();
        this.userEmail = project.getUser().getEmail();
    }
}