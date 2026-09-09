package com.capstone.honeypot.repository;

import com.capstone.honeypot.domain.AttackLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AttackLogRepository extends JpaRepository<AttackLog, Long> {

    List<AttackLog> findByProjectId(Long projectId);
}