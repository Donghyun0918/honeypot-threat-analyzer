package com.capstone.honeypot.service;

import com.capstone.honeypot.domain.TestEntity;
import com.capstone.honeypot.repository.TestRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class TestService {

    private final TestRepository testRepository;

    public TestEntity save(String name) {
        TestEntity entity = new TestEntity();
        entity.setName(name);
        return testRepository.save(entity);
    }

    public List<TestEntity> findAll() {
        return testRepository.findAll();
    }
}