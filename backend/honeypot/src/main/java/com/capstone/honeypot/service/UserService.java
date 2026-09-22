package com.capstone.honeypot.service;

import com.capstone.honeypot.config.JwtUtil;
import com.capstone.honeypot.domain.User;
import com.capstone.honeypot.dto.*;
import com.capstone.honeypot.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final LoginAttemptService loginAttempts;

    /**
     * 로그인 실패 시 내보내는 문구. <b>하나로 통일한다.</b>
     *
     * <p>전에는 "존재하지 않는 이메일입니다" 와 "비밀번호가 일치하지 않습니다" 로
     * 갈라져 있었다. 응답만 보고 <b>어떤 이메일이 가입돼 있는지 확인할 수 있다</b>는
     * 뜻이고(계정 열거), 공격자가 비밀번호를 찍기 전에 표적 목록부터 추린다.
     * 사용자 입장에서 잃는 편의는 적고, 알려주는 정보는 크다.
     */
    private static final String 로그인실패 = "이메일 또는 비밀번호가 올바르지 않습니다.";

    public UserResponse signup(UserSignupRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("이미 사용 중인 이메일입니다.");
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setName(request.getName());
        user.setRole("USER");

        return new UserResponse(userRepository.save(user));
    }

    public UserLoginResponse login(UserLoginRequest request, String 관측출처) {
        String email = request.getEmail();

        long 남은초 = loginAttempts.남은차단초(email);
        if (남은초 > 0) {
            // 비밀번호를 맞게 넣었더라도 여기서 끊는다. 맞았는지 아닌지를
            // 알려주면 차단 자체가 신탁(oracle)이 되어 의미가 없어진다.
            throw new ResponseStatusException(
                    HttpStatus.TOO_MANY_REQUESTS,
                    "로그인 시도가 너무 많습니다. " + ((남은초 + 59) / 60) + "분 후 다시 시도하세요.");
        }

        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null || !passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            loginAttempts.실패기록(email, 관측출처);
            throw new IllegalArgumentException(로그인실패);
        }

        loginAttempts.성공기록(email);
        return new UserLoginResponse(jwtUtil.generateToken(user.getEmail()));
    }

    public EmailCheckResponse checkEmail(String email) {
        boolean exists = userRepository.existsByEmail(email);

        if (exists) {
            return new EmailCheckResponse(email, false, "이미 사용 중인 이메일입니다.");
        }

        return new EmailCheckResponse(email, true, "사용 가능한 이메일입니다.");
    }

    public List<UserResponse> findAllUsers() {
        return userRepository.findAll().stream()
                .map(UserResponse::new)
                .toList();
    }

    public UserResponse findUserById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("사용자 없음"));

        return new UserResponse(user);
    }
}