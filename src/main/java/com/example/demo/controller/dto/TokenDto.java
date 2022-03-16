package com.example.demo.controller.dto;

import java.time.Instant;

public record TokenDto(TokenType tokenType, String tokenValue, Long duration, Instant expiryDate) {}
