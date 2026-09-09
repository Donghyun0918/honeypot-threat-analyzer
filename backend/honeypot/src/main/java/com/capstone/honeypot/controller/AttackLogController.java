package com.capstone.honeypot.controller;

import com.capstone.honeypot.dto.AttackLogRequest;
import com.capstone.honeypot.dto.AttackLogResponse;
import com.capstone.honeypot.service.AttackLogService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/attack-logs")
@RequiredArgsConstructor
public class AttackLogController {

    private final AttackLogService attackLogService;

    @PostMapping
    public AttackLogResponse save(@RequestBody AttackLogRequest request) {
        return attackLogService.save(request);
    }

    @GetMapping("/{projectId}")
    public List<AttackLogResponse> findByProject(@PathVariable Long projectId) {
        return attackLogService.findByProject(projectId);
    }
}