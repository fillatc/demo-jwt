package com.example.demo.service;

import com.example.demo.config.SecurityProperties;
import com.example.demo.controller.dto.TokenDto;
import com.example.demo.controller.dto.TokenType;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static com.example.demo.config.SecurityProperties.FINGERPRINT_COOKIE_NAME;

@Service
@AllArgsConstructor
public class CookieServiceImpl implements CookieService {

    private static final String COOKIE_HOST_PREFIX = "__Host-";

    private final TokenService tokenService;
    private final SecurityProperties securityProperties;

    public List<String> generateCookies(final String subject) throws NoSuchAlgorithmException {
        List<String> cookies = new ArrayList<>();
        String userFingerprint = tokenService.generateUserFingerprint();
        String userFingerprintHash = tokenService.generateUserFingerprintHash(userFingerprint);
        TokenDto accessToken = tokenService.generateAccessToken(subject, userFingerprintHash);
        TokenDto refreshToken = tokenService.generateRefreshToken(subject, userFingerprintHash);

        cookies.add(createCookie(accessToken));
        cookies.add(createCookie(refreshToken));
        if (securityProperties.getCookie().isWithFingerprint()) {
            cookies.add(createHardenedCookie(userFingerprint));
        }
        return cookies;
    }

    public List<String> deleteCookies() {
        return Stream.of(
                deleteCookie(securityProperties.getAccessToken().getCookieName()),
                deleteCookie(securityProperties.getRefreshToken().getCookieName()),
                deleteCookie(FINGERPRINT_COOKIE_NAME)
        ).toList();
    }



    private String createCookie(TokenDto token) {
        StringBuilder cookieName = new StringBuilder();
        if (securityProperties.getCookie().isPrefixEnabled()) {
            cookieName.append(COOKIE_HOST_PREFIX);
        }

        cookieName.append(token.tokenType() == TokenType.ACCESS ?
                securityProperties.getAccessToken().getCookieName() :
                securityProperties.getRefreshToken().getCookieName());

        ResponseCookie.ResponseCookieBuilder cookieBuilder =
                ResponseCookie.from(cookieName.toString(), token.tokenValue())
                .maxAge(token.duration())
                .httpOnly(securityProperties.getCookie().isHttpOnly())
                .secure(securityProperties.getCookie().isSecure())
                .sameSite(securityProperties.getCookie().getSameSite())
                .path(securityProperties.getCookie().getPath())
                .domain(securityProperties.getCookie().getDomain());
        return cookieBuilder.build().toString();
    }

    private String createHardenedCookie(String userFingerprint) {
        return ResponseCookie.from(FINGERPRINT_COOKIE_NAME, userFingerprint)
                .sameSite("Strict")
                .httpOnly(true)
                .secure(true)
                .build()
                .toString();
    }

    private String deleteCookie(final String cookieName) {
        return ResponseCookie.from(cookieName, "")
                .maxAge(0)
                .httpOnly(securityProperties.getCookie().isHttpOnly())
                .secure(securityProperties.getCookie().isSecure())
                .sameSite(securityProperties.getCookie().getSameSite())
                .path(securityProperties.getCookie().getPath())
                .domain(securityProperties.getCookie().getDomain())
                .build()
                .toString();
    }
}
