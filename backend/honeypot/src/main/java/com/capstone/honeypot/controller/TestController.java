package com.capstone.honeypot.controller;

import com.capstone.honeypot.domain.TestEntity;
import com.capstone.honeypot.service.TestService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/test")
@RequiredArgsConstructor
public class TestController {

    private final TestService testService;

    @GetMapping("/save")
    public TestEntity save(@RequestParam String name) {
        return testService.save(name);
    }

    @GetMapping
    public List<TestEntity> findAll() {
        return testService.findAll();
    }
}