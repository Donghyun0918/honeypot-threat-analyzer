package com.capstone.honeypot.controller;

import com.capstone.honeypot.domain.Project;
import com.capstone.honeypot.domain.User;
import com.capstone.honeypot.dto.AttackLogRequest;
import com.capstone.honeypot.dto.AttackLogResponse;
import com.capstone.honeypot.dto.InternalAttackLogRequest;
import com.capstone.honeypot.repository.ProjectRepository;
import com.capstone.honeypot.repository.UserRepository;
import com.capstone.honeypot.service.AttackLogService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/internal")
@RequiredArgsConstructor
public class InternalController {

    @Value("${internal.service-token:}")
    private String serviceToken;

    /**
     * 공유 비밀이 비어 있으면 임의 값으로 채운다.
     *
     * <p>이전에는 {@code honeypot-internal-token} 이 기본값이었다. 이 엔드포인트는
     * Spring Security 에서 permitAll 이고 토큰만으로 지켜지므로, 저장소를 읽은
     * 사람은 누구나 임의의 공격 로그를 사용자 계정까지 자동 생성해 가며
     * 밀어넣을 수 있었다.
     *
     * <p>비어 있을 때 통과시키지 않고 <b>아무도 모르는 값</b>으로 막는다.
     * 외부 수집기를 붙이려면 {@code INTERNAL_SERVICE_TOKEN} 을 설정해야 한다 —
     * 설정을 잊으면 조용히 열리는 대신 붙지 않는 쪽이 안전하다.
     */
    @PostConstruct
    void 토큰확인() {
        if (serviceToken == null || serviceToken.isBlank()) {
            serviceToken = java.util.UUID.randomUUID().toString();
            log.warn("INTERNAL_SERVICE_TOKEN 이 설정되지 않아 임의 값을 생성했습니다. "
                    + "/api/internal/** 로 들어오는 호출은 모두 거부됩니다. "
                    + "외부 수집기를 붙이려면 .env 에 INTERNAL_SERVICE_TOKEN 을 설정하세요.");
        }
    }

    private final UserRepository userRepository;
    private final ProjectRepository projectRepository;
    private final AttackLogService attackLogService;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/attack-log")
    public ResponseEntity<?> saveAttackLog(
            @RequestHeader("X-Service-Token") String token,
            @RequestBody InternalAttackLogRequest request
    ) {
        if (!serviceToken.equals(token)) {
            return ResponseEntity.status(403).body("Invalid service token");
        }

        // 입력 검증. 이게 없을 때 본문 `{}` 를 보내면 username 이 null 인 채로
        // 아래 사용자 자동 생성까지 내려가 "null@honeypot.local" 을 INSERT 하려다
        // name 의 not-null 제약에 걸려 500 이 났다. 잘못은 호출자에게 있는데
        // 서버 장애로 보이고, 검증 전에 쓰기를 먼저 시도한다는 점이 더 문제다.
        //
        // @Valid 를 쓰지 않는 이유: 인자 바인딩 단계에서 돌기 때문에 토큰 검사보다
        // 먼저 실행된다. 그러면 틀린 토큰으로도 400 이 나가 본문 스키마를 떠본다.
        // 인증이 먼저다.
        List<String> missing = new java.util.ArrayList<>();
        if (isBlank(request.getUsername()))   missing.add("username");
        if (isBlank(request.getAttackType())) missing.add("attackType");
        if (isBlank(request.getIpAddress()))  missing.add("ipAddress");
        if (!missing.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "message", "필수 항목이 비어 있습니다: " + String.join(", ", missing),
                    "status", 400));
        }

        // 유저 없으면 자동 생성 (FastAPI 계정과 동기화)
        String email = request.getUsername() + "@honeypot.local";
        User user = userRepository.findByEmail(email).orElseGet(() -> {
            User u = new User();
            u.setEmail(email);
            u.setName(request.getUsername());
            u.setPassword(passwordEncoder.encode("honeypot-internal"));
            u.setRole("USER");
            return userRepository.save(u);
        });

        // 프로젝트 없으면 기본 프로젝트 자동 생성
        List<Project> projects = projectRepository.findByUserId(user.getId());
        Project project;
        if (projects.isEmpty()) {
            project = new Project();
            project.setName("허니팟 프로젝트");
            project.setDescription("자동 생성된 기본 프로젝트");
            project.setUser(user);
            project = projectRepository.save(project);
        } else {
            project = projects.get(0);
        }

        AttackLogRequest logRequest = new AttackLogRequest();
        logRequest.setAttackType(request.getAttackType());
        logRequest.setPayload(request.getPayload());
        logRequest.setIpAddress(request.getIpAddress());
        logRequest.setProjectId(project.getId());

        AttackLogResponse response = attackLogService.save(logRequest);
        return ResponseEntity.ok(response);
    }

    private static boolean isBlank(String v) {
        return v == null || v.isBlank();
    }
}
