package com.capstone.honeypot.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

/**
 * 사용자가 적어둔 자산 포트 목록.
 *
 * <p>허니팟 데이터는 "우리 대역을 노리는 공격" 이지 "우리가 뚫렸다" 가 아니다.
 * 열어둔 포트를 대야 내 얘기가 되는데, 그 목록은 브라우저에만 두면 기기를
 * 바꿀 때마다 사라진다. 여러 사람이 같은 센서를 공유하는 SaaS 형태에서는
 * <b>공격 데이터는 공유하되 자산 대조는 계정별</b>이어야 하므로 여기에 둔다.
 *
 * <p>원문을 그대로 보관한다. 사용자는 "웹서버 80, 443" 처럼 이름을 붙여 적고,
 * 포트만 뽑아 저장하면 그 맥락이 사라져 다시 열었을 때 자기가 뭘 적었는지
 * 알아볼 수 없다. 포트 추출은 조회할 때 한다.
 *
 * <p><b>민감한 정보다.</b> "어느 조직이 어떤 포트를 열어놨는가" 라는 목록이므로
 * 로그에 남기지 않고, 조회는 반드시 본인 것만 돌려준다.
 */
@Entity
@Getter
@Setter
public class AssetProfile {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** 사용자당 하나. 계정이 지워지면 함께 지운다. */
    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private User user;

    @Column(columnDefinition = "TEXT")
    private String rawText;

    private LocalDateTime updatedAt;

    @PrePersist
    @PreUpdate
    void 시각갱신() {
        this.updatedAt = LocalDateTime.now();
    }
}
