package com.example.demo.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.demo.config.SecurityProperties;
import com.example.demo.controller.dto.TokenDto;
import com.example.demo.controller.dto.TokenType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.*;
import java.util.Date;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;
import static com.example.demo.utils.Utils.bytesToHex;
import static org.springframework.util.Assert.hasText;
import static org.springframework.util.Assert.isTrue;

@Slf4j
@Service
public class TokenServiceImpl implements TokenService {

    private static final String TOKEN_TYPE = "tokenType";
    private static final String USER_FINGER_PRINT_HASH = "userFingerprintHash";

    private final SecurityProperties securityProperties;
    private final Algorithm algorithm;
    private final JWTVerifier verifier;
    private final SecureRandom secureRandom;
    private final Clock clock;

    public TokenServiceImpl(SecurityProperties securityProperties, Clock clock) {
        this.securityProperties = securityProperties;
        this.algorithm = HMAC512(securityProperties.getTokenSecret());
        this.verifier = JWT.require(algorithm)
                .withIssuer(securityProperties.getTokenIssuer())
                .build();
        this.secureRandom = new SecureRandom();
        this.clock = clock;
    }

    public String getUsernameFromToken(String token) {
        return verifier.verify(token).getSubject();
    }

    public boolean validateToken(String token, String fingerprint) {
        try {
            hasText(token, "Token doesn't contain any value!");
            DecodedJWT jwt = verifier.verify(token);
            if (securityProperties.getCookie().isWithFingerprint()) {
                String fingerprintHash = jwt.getClaim(USER_FINGER_PRINT_HASH).asString();
                hasText(fingerprint, "Cookie fingerprint doesn't contain any value!");
                hasText(fingerprintHash, "FingerprintHash doesn't contain any value!");
                isTrue(fingerprintHash.equals(generateUserFingerprintHash(fingerprint)), "Fingerprint doesn't match!");
            }
            return true;
        } catch (Exception exception) {
            log.error("JWT validation failed: ", exception);
        }
        return false;
    }

    public TokenDto generateAccessToken(String subject, String userFingerprintHash) {
        return generateToken(securityProperties.getAccessToken(), subject, TokenType.ACCESS, userFingerprintHash);
    }

    public TokenDto generateRefreshToken(String subject, String userFingerprintHash) {
        return generateToken(securityProperties.getRefreshToken(), subject, TokenType.REFRESH, userFingerprintHash);
    }

    private TokenDto generateToken(final SecurityProperties.Token tokenProperties,
                                   final String subject,
                                   final TokenType tokenType,
                                   final String userFingerprintHash) {

        Instant now = Instant.now(clock);
        Instant expiryDate = now.plusSeconds(tokenProperties.getExpiration());

        String tokenValue = JWT.create()
                .withIssuer(securityProperties.getTokenIssuer())
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(expiryDate))
                .withSubject(subject)
                .withClaim(TOKEN_TYPE, tokenType.toString())
                .withClaim(USER_FINGER_PRINT_HASH, userFingerprintHash)
                .sign(algorithm);

        return new TokenDto(tokenType, tokenValue, tokenProperties.getExpiration(), expiryDate);
    }


    public String generateUserFingerprint() {
        if (securityProperties.getCookie().isWithFingerprint()) {
            byte[] randomFgp = new byte[50];
            secureRandom.nextBytes(randomFgp);
            return bytesToHex(randomFgp);
        }
        return null;
    }

    public String generateUserFingerprintHash(final String userFingerprint) throws NoSuchAlgorithmException {
        if (securityProperties.getCookie().isWithFingerprint()) {
            hasText(userFingerprint, "Can't generate fingerprint hash, fingerprint doesn't contain any value!");
            MessageDigest digest = MessageDigest.getInstance("SHA3-256");
            byte[] userFingerprintDigest = digest.digest(userFingerprint.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(userFingerprintDigest);
        }
        return null;
    }
}