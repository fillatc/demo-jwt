package com.example.demo.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Getter
@Setter
@Validated
@Configuration
@ConfigurationProperties(prefix = "application.auth")
public class SecurityProperties {

    public static final String FINGERPRINT_COOKIE_NAME = "__Secure-Fpg";

    @Size(min = 64, message = "{application.auth.token-secret too short}")
    private String tokenSecret;

    @NotBlank
    private String tokenIssuer;

    private Token accessToken;

    private Token refreshToken;

    private Cookie cookie;

    @Getter
    @Setter
    public static class Token {

        @NotBlank
        private String cookieName;

        @NotNull
        private Long expiration;
    }

    @Getter
    @Setter
    public static class Cookie {

        private boolean withFingerprint;
        private boolean prefixEnabled;
        private boolean httpOnly;
        private boolean secure;
        private String sameSite;
        private String path;
        private String domain;
    }
}

