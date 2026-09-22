package com.capstone.honeypot.repository;

import com.capstone.honeypot.domain.AssetProfile;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AssetProfileRepository extends JpaRepository<AssetProfile, Long> {
    Optional<AssetProfile> findByUserEmail(String email);
}
