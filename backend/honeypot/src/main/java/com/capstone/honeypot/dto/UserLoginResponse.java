package com.capstone.honeypot.dto;

import lombok.Getter;

@Getter
public class UserLoginResponse {

    private final String token;
    private final String message;

    public UserLoginResponse(String token) {
        this.token = token;
        this.message = "로그인 성공";
    }
}