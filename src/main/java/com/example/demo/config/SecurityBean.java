package com.example.demo.config;

import com.example.demo.service.CookieService;
import com.example.demo.service.CustomUserDetailsServiceImpl;
import com.example.demo.service.TokenService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityBean {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter(final TokenService tokenProvider,
                                                               final CookieService cookieService,
                                                               final SecurityProperties securityProperties,
                                                               final CustomUserDetailsServiceImpl customUserDetailsService) {

        return new TokenAuthenticationFilter(tokenProvider,
                cookieService,
                securityProperties,
                customUserDetailsService);
    }
}