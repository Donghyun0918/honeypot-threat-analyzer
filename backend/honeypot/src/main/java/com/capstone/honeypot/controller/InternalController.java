package com.capstone.honeypot.controller;

import com.capstone.honeypot.domain.Project;
import com.capstone.honeypot.domain.User;
import com.capstone.honeypot.dto.AttackLogRequest;
import com.capstone.honeypot.dto.AttackLogResponse;
import com.capstone.honeypot.dto.InternalAttackLogRequest;
import com.capstone.honeypot.repository.ProjectRepository;
import com.capstone.honeypot.repository.UserRepository;
import com.capstone.honeypot.service.AttackLogService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/internal")
@RequiredArgsConstructor
public class InternalController {

    @Value("${internal.service-token}")
    private String serviceToken;

    private final UserRepository userRepository;
    private final ProjectRepository projectRepository;
    private final AttackLogService attackLogService;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/attack-log")
    public ResponseEntity<?> saveAttackLog(
            @RequestHeader("X-Service-Token") String token,
            @RequestBody InternalAttackLogRequest request
    ) {
        if (!serviceToken.equals(token)) {
            return ResponseEntity.status(403).body("Invalid service token");
        }

        // 유저 없으면 자동 생성 (FastAPI 계정과 동기화)
        String email = request.getUsername() + "@honeypot.local";
        User user = userRepository.findByEmail(email).orElseGet(() -> {
            User u = new User();
            u.setEmail(email);
            u.setName(request.getUsername());
            u.setPassword(passwordEncoder.encode("honeypot-internal"));
            u.setRole("USER");
            return userRepository.save(u);
        });

        // 프로젝트 없으면 기본 프로젝트 자동 생성
        List<Project> projects = projectRepository.findByUserId(user.getId());
        Project project;
        if (projects.isEmpty()) {
            project = new Project();
            project.setName("허니팟 프로젝트");
            project.setDescription("자동 생성된 기본 프로젝트");
            project.setUser(user);
            project = projectRepository.save(project);
        } else {
            project = projects.get(0);
        }

        AttackLogRequest logRequest = new AttackLogRequest();
        logRequest.setAttackType(request.getAttackType());
        logRequest.setPayload(request.getPayload());
        logRequest.setIpAddress(request.getIpAddress());
        logRequest.setProjectId(project.getId());

        AttackLogResponse response = attackLogService.save(logRequest);
        return ResponseEntity.ok(response);
    }
}
