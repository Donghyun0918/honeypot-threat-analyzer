package com.capstone.honeypot.repository;

import com.capstone.honeypot.domain.AnalysisResult;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface AnalysisResultRepository extends JpaRepository<AnalysisResult, Long> {

    Optional<AnalysisResult> findByAttackLogId(Long attackLogId);

    /**
     * 여러 로그의 분석 결과를 한 번에 가져온다.
     *
     * <p>로그마다 {@link #findByAttackLogId} 를 부르면 로그 N 건에 쿼리가 N+1 번
     * 나간다. 목록 화면처럼 한꺼번에 필요한 경우에는 이 메서드로 한 번에 받는다.
     */
    List<AnalysisResult> findByAttackLogIdIn(Collection<Long> attackLogIds);
}