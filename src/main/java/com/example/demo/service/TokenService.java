package com.example.demo.service;

import com.example.demo.controller.dto.TokenDto;

import java.security.NoSuchAlgorithmException;

public interface TokenService {

    String getUsernameFromToken(String token);

    boolean validateToken(String token, String fingerprint);

    TokenDto generateAccessToken(String subject, String userFingerprintHash);

    TokenDto generateRefreshToken(String subject, String userFingerprintHash);

    String generateUserFingerprint();

    String generateUserFingerprintHash(final String userFingerprint) throws NoSuchAlgorithmException;
}