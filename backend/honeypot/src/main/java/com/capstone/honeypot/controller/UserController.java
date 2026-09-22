package com.capstone.honeypot.controller;

import com.capstone.honeypot.dto.*;
import com.capstone.honeypot.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/signup")
    public UserResponse signup(@RequestBody UserSignupRequest request) {
        return userService.signup(request);
    }

    @PostMapping("/login")
    public UserLoginResponse login(@RequestBody UserLoginRequest request,
                                   HttpServletRequest http) {
        // 이 주소는 차단 기준이 아니라 로그용이다. 브라우저는 Spring 을 직접
        // 부르지 않으므로 여기 찍히는 건 대개 프론트 컨테이너다
        // (LoginAttemptService 의 설명 참조).
        return userService.login(request, http.getRemoteAddr());
    }

    @GetMapping("/check-email")
    public EmailCheckResponse checkEmail(@RequestParam String email) {
        return userService.checkEmail(email);
    }

    @GetMapping
    public List<UserResponse> findAllUsers() {
        return userService.findAllUsers();
    }

    @GetMapping("/{id}")
    public UserResponse findUserById(@PathVariable Long id) {
        return userService.findUserById(id);
    }

    @GetMapping("/me")
    public String me(HttpServletRequest request) {
        return (String) request.getAttribute("email");
    }
}