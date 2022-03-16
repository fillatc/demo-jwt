package com.example.demo.config;

import com.example.demo.service.CookieService;
import com.example.demo.service.CustomUserDetailsServiceImpl;
import com.example.demo.service.TokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.userdetails.User;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class TokenAuthenticationFilterTest {

    @Mock
    private TokenService tokenProvider;
    @Mock
    private CookieService cookieService;
    @Mock
    private SecurityProperties securityProperties;
    @Mock
    private CustomUserDetailsServiceImpl customUserDetailsService;
    @InjectMocks
    private TokenAuthenticationFilter filter;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockFilterChain filterChain;

    @BeforeEach
    public void setup() {
        this.request = new MockHttpServletRequest();
        this.request.setScheme("http");
        this.request.setServerName("localhost");
        this.request.setServerPort(80);
        this.response = new MockHttpServletResponse();
        this.filterChain = new MockFilterChain(new HttpServlet() {});
    }

    @Test
    void test_TokenAuthenticationFilter___without_token___expect_no_authentication_and_no_cookie_generation() {
        // GIVEN
        SecurityProperties.Token accessToken = new SecurityProperties.Token();
        accessToken.setCookieName("accessCookieName");
        when(securityProperties.getAccessToken()).thenReturn(accessToken);
        SecurityProperties.Token refreshToken = new SecurityProperties.Token();
        refreshToken.setCookieName("refreshCookieName");
        when(securityProperties.getRefreshToken()).thenReturn(refreshToken);

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        verify(tokenProvider, times(2)).validateToken(null, null);
        verifyNoInteractions(cookieService);
        verifyNoInteractions(customUserDetailsService);
    }

    @Test
    void test_TokenAuthenticationFilter___with_valid_access_token___expect_authentication_and_no_cookie_generation() {
        // GIVEN
        this.request.setCookies(new Cookie("accessCookieName", "tokenValue"));

        SecurityProperties.Token accessToken = new SecurityProperties.Token();
        accessToken.setCookieName("accessCookieName");
        when(securityProperties.getAccessToken()).thenReturn(accessToken);
        SecurityProperties.Token refreshToken = new SecurityProperties.Token();
        refreshToken.setCookieName("refreshCookieName");
        when(securityProperties.getRefreshToken()).thenReturn(refreshToken);
        when(tokenProvider.validateToken("tokenValue", null)).thenReturn(true);
        when(tokenProvider.getUsernameFromToken("tokenValue")).thenReturn("username");
        when(customUserDetailsService.loadUserByUsername("username")).thenReturn(new User("username", "pwd", new ArrayList<>()));

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        verify(customUserDetailsService, times(1)).loadUserByUsername("username");
        verify(tokenProvider, times(1)).validateToken("tokenValue", null);
        verifyNoInteractions(cookieService);
    }

    @Test
    void test_TokenAuthenticationFilter___with_valid_refresh_token___expect_authentication_and_cookie_generation() throws NoSuchAlgorithmException {
        // GIVEN
        this.request.setCookies(new Cookie("refreshCookieName", "refreshTokenValue"),
                new Cookie("accessCookieName", "accessTokenValue"));

        SecurityProperties.Token accessToken = new SecurityProperties.Token();
        accessToken.setCookieName("accessCookieName");
        when(securityProperties.getAccessToken()).thenReturn(accessToken);
        SecurityProperties.Token refreshToken = new SecurityProperties.Token();
        refreshToken.setCookieName("refreshCookieName");
        when(securityProperties.getRefreshToken()).thenReturn(refreshToken);
        when(tokenProvider.validateToken("accessTokenValue", null)).thenReturn(false);
        when(tokenProvider.validateToken("refreshTokenValue", null)).thenReturn(true);
        when(tokenProvider.getUsernameFromToken("refreshTokenValue")).thenReturn("username");
        when(customUserDetailsService.loadUserByUsername("username")).thenReturn(new User("username", "pwd", new ArrayList<>()));
        when(cookieService.generateCookies("username"))
                .thenReturn(List.of(
                        "accessCookieName=accessToken; Max-Age=100; Expires=Wed, 27 Apr 2022 21:29:03 GMT",
                        "refreshCookieName=refreshToken; Max-Age=100; Expires=Wed, 28 Apr 2022 21:29:03 GMT"));

        // WHEN
        filter.doFilterInternal(request, response, filterChain);

        // THEN
        assertThat(response).isNotNull();
        assertThat(response.getCookies()).hasSize(2);
        assertThat(response.getCookies())
                .extracting(Cookie::getName)
                .contains("accessCookieName", "refreshCookieName");

        verify(customUserDetailsService, times(1)).loadUserByUsername("username");
        verify(cookieService, times(1)).generateCookies("username");
    }
}
