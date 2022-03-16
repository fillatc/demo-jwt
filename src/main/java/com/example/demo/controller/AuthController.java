package com.example.demo.controller;

import com.example.demo.controller.dto.LoginDto;
import com.example.demo.service.CookieService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletResponse;
import java.security.NoSuchAlgorithmException;
import java.util.List;

@Controller
@AllArgsConstructor
public class AuthController {

    private final CookieService cookieService;
    private final AuthenticationManager authenticationManager;

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @PostMapping(value = "/login")
    public String login(LoginDto loginDto, HttpServletResponse response) throws NoSuchAlgorithmException {
        authentication(response, loginDto.login(), loginDto.password());
        return "home";
    }

    @GetMapping("/logout")
    public String logout(HttpServletResponse response) {
        cookieService.deleteCookies()
                .forEach(value -> response.addHeader(HttpHeaders.SET_COOKIE, value));
        return "/index";
    }

    private void authentication(HttpServletResponse response, String login, String password) throws NoSuchAlgorithmException {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(login, password));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        List<String> cookies = cookieService.generateCookies(login);
        cookies.forEach(value -> response.addHeader(HttpHeaders.SET_COOKIE, value));
    }
}
