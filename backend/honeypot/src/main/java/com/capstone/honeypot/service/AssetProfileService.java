package com.capstone.honeypot.service;

import com.capstone.honeypot.domain.AssetProfile;
import com.capstone.honeypot.domain.User;
import com.capstone.honeypot.repository.AssetProfileRepository;
import com.capstone.honeypot.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 자산 포트 목록 조회·저장. 언제나 <b>본인 것만</b> 다룬다.
 *
 * <p>읽기에도 트랜잭션 경계를 두는 이유는 {@code AssetProfile.user} 가 LAZY 라
 * 경계 밖에서 접근하면 {@code LazyInitializationException} 이 나기 때문이다
 * ({@code spring.jpa.open-in-view=false}).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AssetProfileService {

    /** 사람이 자산 목록에 적을 만한 길이를 넘는 입력은 받지 않는다. */
    private static final int 최대길이 = 4000;

    private final AssetProfileRepository assetProfileRepository;
    private final UserRepository userRepository;

    @Transactional(readOnly = true)
    public String 읽기(String email) {
        return assetProfileRepository.findByUserEmail(email)
                .map(AssetProfile::getRawText)
                .orElse("");
    }

    @Transactional
    public String 저장(String email, String rawText) {
        String 값 = rawText == null ? "" : rawText;
        if (값.length() > 최대길이) {
            throw new IllegalArgumentException(
                    "자산 목록이 너무 깁니다(" + 최대길이 + "자 이내).");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("해당 사용자가 없습니다. email=" + email));

        AssetProfile profile = assetProfileRepository.findByUserEmail(email)
                .orElseGet(() -> {
                    AssetProfile p = new AssetProfile();
                    p.setUser(user);
                    return p;
                });
        profile.setRawText(값);
        assetProfileRepository.save(profile);

        // 내용은 로그에 남기지 않는다 — "어느 조직이 어떤 포트를 열어놨는가" 다.
        log.debug("자산 목록 저장 ({}자)", 값.length());
        return 값;
    }
}
