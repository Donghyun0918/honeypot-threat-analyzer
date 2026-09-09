package com.capstone.honeypot.repository;

import com.capstone.honeypot.domain.TestEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TestRepository extends JpaRepository<TestEntity, Long> {
}