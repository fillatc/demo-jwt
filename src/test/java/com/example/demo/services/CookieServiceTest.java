package com.example.demo.services;

import com.example.demo.config.SecurityProperties;
import com.example.demo.service.CookieService;
import com.example.demo.service.CookieServiceImpl;
import com.example.demo.service.TokenService;
import com.example.demo.service.TokenServiceImpl;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;


@ExtendWith(MockitoExtension.class)
class CookieServiceTest {

    @Mock
    private SecurityProperties securityProperties;

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void test_generateCookies___without_fingerprint(boolean withPrefixEnabled) throws NoSuchAlgorithmException {
        // GIVEN
        SecurityProperties.Cookie cookie = new SecurityProperties.Cookie();
        cookie.setPrefixEnabled(withPrefixEnabled);
        cookie.setHttpOnly(false);
        cookie.setSecure(false);
        cookie.setWithFingerprint(false);
        when(securityProperties.getCookie()).thenReturn(cookie);
        when(securityProperties.getTokenSecret()).thenReturn("secret");

        SecurityProperties.Token accessToken = new SecurityProperties.Token();
        accessToken.setExpiration(100L);
        accessToken.setCookieName("accessCookieName");
        when(securityProperties.getAccessToken()).thenReturn(accessToken);

        SecurityProperties.Token refreshToken = new SecurityProperties.Token();
        refreshToken.setExpiration(100L);
        refreshToken.setCookieName("refreshCookieName");
        when(securityProperties.getRefreshToken()).thenReturn(refreshToken);

        Instant instant = Instant.now();
        Clock fixed_clock = Clock.fixed(instant, ZoneOffset.UTC);

        TokenService tokenService = new TokenServiceImpl(securityProperties, fixed_clock);
        CookieService cookieService = new CookieServiceImpl(tokenService, securityProperties);

        // WHEN
        List<String> cookies = cookieService.generateCookies("test");

        //THEN
        String prefix = withPrefixEnabled ? "__Host-" : "";
        assertThat(cookies).hasSize(2);
        assertThat(cookies.get(0))
                .startsWith(prefix + "accessCookieName=")
                .contains("; Max-Age=100; Expires=");
        assertThat(cookies.get(1))
                .startsWith(prefix + "refreshCookieName=")
            .contains("; Max-Age=100; Expires=");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void test_generateCookies___with_fingerprint(boolean withPrefixEnabled) throws NoSuchAlgorithmException {
        // GIVEN
        SecurityProperties.Cookie cookie = new SecurityProperties.Cookie();
        cookie.setPrefixEnabled(withPrefixEnabled);
        cookie.setHttpOnly(false);
        cookie.setSecure(false);
        cookie.setWithFingerprint(true);
        when(securityProperties.getCookie()).thenReturn(cookie);
        when(securityProperties.getTokenSecret()).thenReturn("secret");

        SecurityProperties.Token accessToken = new SecurityProperties.Token();
        accessToken.setExpiration(100L);
        accessToken.setCookieName("accessCookieName");
        when(securityProperties.getAccessToken()).thenReturn(accessToken);

        SecurityProperties.Token refreshToken = new SecurityProperties.Token();
        refreshToken.setExpiration(100L);
        refreshToken.setCookieName("refreshCookieName");
        when(securityProperties.getRefreshToken()).thenReturn(refreshToken);

        Instant instant = Instant.now();
        Clock fixed_clock = Clock.fixed(instant, ZoneOffset.UTC);

        TokenService tokenService = new TokenServiceImpl(securityProperties, fixed_clock);
        CookieService cookieService = new CookieServiceImpl(tokenService, securityProperties);

        // WHEN
        List<String> cookies = cookieService.generateCookies("test");

        //THEN
        String prefix = withPrefixEnabled ? "__Host-" : "";
        assertThat(cookies).hasSize(3);
        assertThat(cookies.get(0))
                .startsWith(prefix + "accessCookieName=")
                .contains("; Max-Age=100; Expires=");
        assertThat(cookies.get(1))
                .startsWith(prefix + "refreshCookieName=")
                .contains("; Max-Age=100; Expires=");
        assertThat(cookies.get(2))
                .startsWith("__Secure-Fpg=")
                .contains("; Secure; HttpOnly; SameSite=Strict");
    }

}
