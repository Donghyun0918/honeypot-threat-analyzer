package com.capstone.honeypot.dto;

import lombok.Getter;

@Getter
public class EmailCheckResponse {

    private final String email;
    private final boolean available;
    private final String message;

    public EmailCheckResponse(String email, boolean available, String message) {
        this.email = email;
        this.available = available;
        this.message = message;
    }
}