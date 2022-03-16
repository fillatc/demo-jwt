package com.example.demo.config;


import com.example.demo.service.CookieService;
import com.example.demo.service.CustomUserDetailsServiceImpl;
import com.example.demo.service.TokenService;
import lombok.AllArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.java.Log;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Stream;

import static com.example.demo.config.SecurityProperties.FINGERPRINT_COOKIE_NAME;

@AllArgsConstructor
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final TokenService tokenProvider;
    private final CookieService cookieService;
    private final SecurityProperties securityProperties;
    private final CustomUserDetailsServiceImpl customUserDetailsService;

    @SneakyThrows
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) {

        String jwtAccessToken = extractCookieValue(httpServletRequest,
                securityProperties.getAccessToken().getCookieName());
        String jwtRefreshToken = extractCookieValue(httpServletRequest,
                securityProperties.getRefreshToken().getCookieName());
        String fingerprint = extractCookieValue(httpServletRequest, FINGERPRINT_COOKIE_NAME);

        if (tokenProvider.validateToken(jwtAccessToken, fingerprint)) {
            String username = tokenProvider.getUsernameFromToken(jwtAccessToken);
            authenticate(username, httpServletRequest);
        } else if (tokenProvider.validateToken(jwtRefreshToken, fingerprint)) {
            String username = tokenProvider.getUsernameFromToken(jwtRefreshToken);
            List<String> cookies = cookieService.generateCookies(username);
            cookies.forEach(value -> httpServletResponse.addHeader(HttpHeaders.SET_COOKIE, value));
            authenticate(username, httpServletRequest);
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private void authenticate(String username, HttpServletRequest httpServletRequest) {
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
        authentication.setDetails(
                new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private String extractCookieValue(HttpServletRequest request, final String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            return Stream.of(cookies)
                    .filter(cookie -> cookieName.equals(cookie.getName()))
                    .map(Cookie::getValue)
                    .findAny()
                    .orElse(null);
        }
        return null;
    }

}
