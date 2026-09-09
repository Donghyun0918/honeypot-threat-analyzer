package com.capstone.honeypot.controller;

import com.capstone.honeypot.dto.AnalysisResultRequest;
import com.capstone.honeypot.dto.AnalysisResultResponse;
import com.capstone.honeypot.service.AnalysisResultService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/analysis-results")
@RequiredArgsConstructor
public class AnalysisResultController {

    private final AnalysisResultService analysisResultService;

    @PostMapping
    public AnalysisResultResponse save(@RequestBody AnalysisResultRequest request) {
        return analysisResultService.save(request);
    }

    @GetMapping("/{attackLogId}")
    public AnalysisResultResponse findByAttackLogId(@PathVariable Long attackLogId) {
        return analysisResultService.findByAttackLogId(attackLogId);
    }
}