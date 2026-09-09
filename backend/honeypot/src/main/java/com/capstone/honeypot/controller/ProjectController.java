package com.capstone.honeypot.controller;

import com.capstone.honeypot.dto.AttackLogWithAnalysisResponse;
import com.capstone.honeypot.dto.ProjectCreateRequest;
import com.capstone.honeypot.dto.ProjectResponse;
import com.capstone.honeypot.service.AttackLogService;
import com.capstone.honeypot.service.ProjectService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/projects")
@RequiredArgsConstructor
public class ProjectController {

    private final ProjectService projectService;
    private final AttackLogService attackLogService;

    @PostMapping
    public ProjectResponse create(@RequestBody ProjectCreateRequest request,
                                  HttpServletRequest httpRequest) {
        String email = (String) httpRequest.getAttribute("email");
        return projectService.create(request, email);
    }

    @GetMapping
    public List<ProjectResponse> findAll() {
        return projectService.findAll();
    }

    @GetMapping("/{id}")
    public ProjectResponse findById(@PathVariable Long id) {
        return projectService.findById(id);
    }

    @DeleteMapping("/{id}")
    public void delete(@PathVariable Long id) {
        projectService.delete(id);
    }

    @GetMapping("/my")
    public List<ProjectResponse> findMyProjects(HttpServletRequest request) {
        String email = (String) request.getAttribute("email");
        return projectService.findMyProjects(email);
    }

    @GetMapping("/{projectId}/logs")
    public List<AttackLogWithAnalysisResponse> findLogsWithAnalysis(@PathVariable Long projectId) {
        return attackLogService.findLogsWithAnalysisByProject(projectId);
    }
}