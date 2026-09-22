package com.capstone.honeypot.controller;

import com.capstone.honeypot.service.AssetProfileService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 내 자산 포트 목록.
 *
 * <p>사용자 식별은 {@code JwtFilter} 가 넣어둔 {@code email} 속성을 쓴다
 * (다른 컨트롤러와 같은 관례). 경로에 사용자 id 를 받지 않으므로
 * <b>남의 목록을 조회할 방법이 없다.</b>
 */
@RestController
@RequestMapping("/api/assets")
@RequiredArgsConstructor
public class AssetProfileController {

    private final AssetProfileService service;

    @GetMapping
    public Map<String, Object> 읽기(HttpServletRequest request) {
        String email = (String) request.getAttribute("email");
        return 응답(service.읽기(email));
    }

    @PutMapping
    public Map<String, Object> 저장(@RequestBody Map<String, String> body,
                                  HttpServletRequest request) {
        String email = (String) request.getAttribute("email");
        return 응답(service.저장(email, body.get("rawText")));
    }

    private Map<String, Object> 응답(String rawText) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("rawText", rawText == null ? "" : rawText);
        return m;
    }
}
