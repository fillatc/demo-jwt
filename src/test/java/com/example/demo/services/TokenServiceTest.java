package com.example.demo.services;

import com.example.demo.config.SecurityProperties;
import com.example.demo.controller.dto.TokenDto;
import com.example.demo.controller.dto.TokenType;
import com.example.demo.service.TokenService;
import com.example.demo.service.TokenServiceImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;


@ExtendWith(MockitoExtension.class)
class TokenServiceTest {

    @Mock
    private SecurityProperties securityProperties;

    @Test
    void generateAccessToken___without_fingerprint() {
        // GIVEN
        Instant instant = Instant.now();
        Clock fixed_clock = Clock.fixed(instant, ZoneOffset.UTC);

        SecurityProperties.Token accessToken = new SecurityProperties.Token();
        accessToken.setExpiration(100L);

        SecurityProperties.Cookie cookie = new SecurityProperties.Cookie();
        cookie.setWithFingerprint(false);

        when(securityProperties.getTokenSecret()).thenReturn("secret");
        when(securityProperties.getAccessToken()).thenReturn(accessToken);
        when(securityProperties.getCookie()).thenReturn(cookie);

        TokenService tokenService = new TokenServiceImpl(securityProperties, fixed_clock);

        // WHEN
        TokenDto token = tokenService.generateAccessToken("test", null);
        boolean result = tokenService.validateToken(token.tokenValue(), null);

        //THEN
        assertThat(token).isNotNull();
        assertThat(result).isTrue();
        assertThat(token.tokenType()).isEqualTo(TokenType.ACCESS);
        assertThat(token.tokenValue()).isNotBlank();
        assertThat(token.duration()).isEqualTo(100L);
        assertThat(token.expiryDate()).isEqualTo(instant.plusSeconds(100));
    }

    @Test
    void generateRefreshToken___without_fingerprint() {
        // GIVEN
        Instant instant = Instant.now();
        Clock fixed_clock = Clock.fixed(instant, ZoneOffset.UTC);

        SecurityProperties.Token refreshToken = new SecurityProperties.Token();
        refreshToken.setExpiration(100L);

        SecurityProperties.Cookie cookie = new SecurityProperties.Cookie();
        cookie.setWithFingerprint(false);

        when(securityProperties.getTokenSecret()).thenReturn("secret");
        when(securityProperties.getRefreshToken()).thenReturn(refreshToken);
        when(securityProperties.getCookie()).thenReturn(cookie);

        TokenService tokenService = new TokenServiceImpl(securityProperties, fixed_clock);

        // WHEN
        TokenDto token = tokenService.generateRefreshToken("test", null);
        boolean result = tokenService.validateToken(token.tokenValue(), null);

        //THEN
        assertThat(token).isNotNull();
        assertThat(result).isTrue();
        assertThat(token.tokenType()).isEqualTo(TokenType.REFRESH);
        assertThat(token.tokenValue()).isNotBlank();
        assertThat(token.duration()).isEqualTo(100L);
        assertThat(token.expiryDate()).isEqualTo(instant.plusSeconds(100));
    }

    @Test
    void generateAccessToken___without_fingerprint_and_expired_token() {
        // GIVEN
        Instant instant = Instant.now();
        Clock fixed_clock = Clock.fixed(instant, ZoneOffset.UTC);

        SecurityProperties.Token accessToken = new SecurityProperties.Token();
        accessToken.setExpiration(-100L); //generate an expired token

        when(securityProperties.getTokenSecret()).thenReturn("secret");
        when(securityProperties.getAccessToken()).thenReturn(accessToken);

        TokenService tokenService = new TokenServiceImpl(securityProperties, fixed_clock);

        // WHEN
        TokenDto token = tokenService.generateAccessToken("test", null);
        boolean result = tokenService.validateToken(token.tokenValue(), null);

        //THEN
        assertThat(token).isNotNull();
        assertThat(result).isFalse();
        assertThat(token.tokenType()).isEqualTo(TokenType.ACCESS);
        assertThat(token.tokenValue()).isNotBlank();
    }

    @Test
    void generateUserFingerprint___without_fingerprint_properties_flag() {
        // GIVEN
        Clock fixed_clock = Clock.fixed(Instant.now(), ZoneOffset.UTC);
        SecurityProperties.Cookie cookie = new SecurityProperties.Cookie();
        cookie.setWithFingerprint(false);

        when(securityProperties.getTokenSecret()).thenReturn("secret");
        when(securityProperties.getCookie()).thenReturn(cookie);

        TokenService tokenService = new TokenServiceImpl(securityProperties, fixed_clock);

        //WHEN
        String fingerprint = tokenService.generateUserFingerprint();

        // THEN
        assertThat(fingerprint).isNull();
    }

    @Test
    void generateUserFingerprint___with_fingerprint_properties_flag() {
        // GIVEN
        Clock fixed_clock = Clock.fixed(Instant.now(), ZoneOffset.UTC);

        SecurityProperties.Cookie cookie = new SecurityProperties.Cookie();
        cookie.setWithFingerprint(true);

        when(securityProperties.getTokenSecret()).thenReturn("secret");
        when(securityProperties.getCookie()).thenReturn(cookie);

        TokenService tokenService = new TokenServiceImpl(securityProperties, fixed_clock);

        // WHEN
        String fingerprint = tokenService.generateUserFingerprint();

        // THEN
        assertThat(fingerprint)
                .isNotNull()
                .hasSize(100);
    }

    @Test
    void generateUserFingerprintHash___without_fingerprint_properties_flag() throws NoSuchAlgorithmException {
        // GIVEN
        Clock fixed_clock = Clock.fixed(Instant.now(), ZoneOffset.UTC);

        SecurityProperties.Cookie cookie = new SecurityProperties.Cookie();
        cookie.setWithFingerprint(false);

        when(securityProperties.getTokenSecret()).thenReturn("secret");
        when(securityProperties.getCookie()).thenReturn(cookie);

        TokenService tokenService = new TokenServiceImpl(securityProperties, fixed_clock);

        // WHEN
        String fingerprintHash = tokenService.generateUserFingerprintHash("random string");

        // THEN
        assertThat(fingerprintHash).isNull();
    }

    @Test
    void generateUserFingerprintHash___with_fingerprint_properties_flag_and_without_fingerprint() {
        // GIVEN
        Clock fixed_clock = Clock.fixed(Instant.now(), ZoneOffset.UTC);

        SecurityProperties.Cookie cookie = new SecurityProperties.Cookie();
        cookie.setWithFingerprint(true);

        when(securityProperties.getTokenSecret()).thenReturn("secret");
        when(securityProperties.getCookie()).thenReturn(cookie);

        TokenService tokenService = new TokenServiceImpl(securityProperties, fixed_clock);

        // WHEN / THEN
        assertThrows(IllegalArgumentException.class,
                () -> tokenService.generateUserFingerprintHash(null));
    }

    @Test
    void generateUserFingerprintHash___with_fingerprint_properties_flag() throws NoSuchAlgorithmException {
        // GIVEN
        Clock fixed_clock = Clock.fixed(Instant.now(), ZoneOffset.UTC);

        SecurityProperties.Cookie cookie = new SecurityProperties.Cookie();
        cookie.setWithFingerprint(true);

        when(securityProperties.getTokenSecret()).thenReturn("secret");
        when(securityProperties.getCookie()).thenReturn(cookie);

        TokenService tokenService = new TokenServiceImpl(securityProperties, fixed_clock);

        // WHEN
        String fingerprintHash = tokenService.generateUserFingerprintHash("random string");

        // THEN
        assertThat(fingerprintHash)
                .isNotNull()
                .hasSize(64);
    }

    @Test
    void generateAccessToken___with_fingerprint() throws NoSuchAlgorithmException {
        // GIVEN
        Instant instant = Instant.now();
        Clock fixed_clock = Clock.fixed(instant, ZoneOffset.UTC);

        SecurityProperties.Token accessToken = new SecurityProperties.Token();
        accessToken.setExpiration(100L);

        SecurityProperties.Cookie cookie = new SecurityProperties.Cookie();
        cookie.setWithFingerprint(true);

        when(securityProperties.getTokenSecret()).thenReturn("secret");
        when(securityProperties.getAccessToken()).thenReturn(accessToken);
        when(securityProperties.getCookie()).thenReturn(cookie);

        TokenService tokenService = new TokenServiceImpl(securityProperties, fixed_clock);

        // WHEN
        String fingerprint = tokenService.generateUserFingerprint();
        String fingerprintHash = tokenService.generateUserFingerprintHash(fingerprint);
        TokenDto token = tokenService.generateAccessToken("test", fingerprintHash);
        boolean result = tokenService.validateToken(token.tokenValue(), fingerprint);

        //THEN
        assertThat(token).isNotNull();
        assertThat(result).isTrue();
        assertThat(token.tokenType()).isEqualTo(TokenType.ACCESS);
        assertThat(token.tokenValue()).isNotBlank();
        assertThat(token.duration()).isEqualTo(100L);
        assertThat(token.expiryDate()).isEqualTo(instant.plusSeconds(100));
    }


    @ParameterizedTest
    @ValueSource(strings = {"", "  ", "test", "user", "admin"})
    void getUsernameFromToken___(String username) throws NoSuchAlgorithmException {
        // GIVEN
        Instant instant = Instant.now();
        Clock fixed_clock = Clock.fixed(instant, ZoneOffset.UTC);

        SecurityProperties.Token accessToken = new SecurityProperties.Token();
        accessToken.setExpiration(100L);

        SecurityProperties.Cookie cookie = new SecurityProperties.Cookie();
        cookie.setWithFingerprint(true);

        when(securityProperties.getTokenSecret()).thenReturn("secret");
        when(securityProperties.getAccessToken()).thenReturn(accessToken);
        when(securityProperties.getCookie()).thenReturn(cookie);

        TokenService tokenService = new TokenServiceImpl(securityProperties, fixed_clock);

        // WHEN
        String fingerprint = tokenService.generateUserFingerprint();
        String fingerprintHash = tokenService.generateUserFingerprintHash(fingerprint);
        TokenDto token = tokenService.generateAccessToken(username, fingerprintHash);
        String usernameFromToken = tokenService.getUsernameFromToken(token.tokenValue());

        //THEN
        assertThat(token).isNotNull();
        assertThat(usernameFromToken).isEqualTo(username);
        assertThat(token.tokenType()).isEqualTo(TokenType.ACCESS);
        assertThat(token.tokenValue()).isNotBlank();
        assertThat(token.duration()).isEqualTo(100L);
        assertThat(token.expiryDate()).isEqualTo(instant.plusSeconds(100));
    }
}
