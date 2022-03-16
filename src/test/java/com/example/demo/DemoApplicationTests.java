package com.example.demo;

import com.example.demo.controller.dto.TokenDto;
import com.example.demo.service.TokenService;
import org.hamcrest.core.StringContains;
import org.hamcrest.core.StringStartsWith;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.http.Cookie;


import static org.hamcrest.Matchers.contains;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(classes = {DemoApplication.class},
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class DemoApplicationTests {

    @Autowired
    private TokenService tokenService;

    @Autowired
    private WebApplicationContext webApplicationContext;

    private MockMvc mockMvc;

    @BeforeEach
    public void setup() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(this.webApplicationContext).build();
    }

    @ParameterizedTest
    @CsvSource({"/index,index", "/,index", "/login,login", "/home,home", "/logout,/index"})
    void givenPageURI_whenMockMVC_thenReturnsView(String request, String view) throws Exception {
        this.mockMvc.perform(get(request))
                .andDo(print())
                .andExpect(view().name(view))
                .andExpect(status().isOk());
    }

    @Test
    void givenLoginPageURI_whenMockMVC_thenReturnsCookiesToken() throws Exception {
        this.mockMvc.perform(post("/login")
                        .param("login", "admin")
                        .param("password", "admin"))
                .andDo(print())
                .andExpect(view().name("home"))
                .andExpect(status().isOk())
                .andExpect(header().exists("Set-Cookie"))
                .andExpect(header()
                        .stringValues("Set-Cookie", contains(
                                new StringStartsWith("accessToken"),
                                new StringContains("refreshToken"))
                        )
                );
    }

    @Test
    void givenHomePageURI_whenMockMVC_then() throws Exception {
        TokenDto token = tokenService.generateAccessToken("admin", null);
        this.mockMvc.perform(get("/home").cookie(new Cookie("accessToken", token.tokenValue())))
                .andDo(print())
                .andExpect(view().name("home"))
                .andExpect(status().isOk());
    }

    @Test
    void givenHomePageURI_whenMockMVC_then_() throws Exception {
        TokenDto token = tokenService.generateRefreshToken("admin", null);
        this.mockMvc.perform(get("/home")
                        .cookie(
                                new Cookie("accessToken", "invalidToken"),
                                new Cookie("refreshToken", token.tokenValue())
                        ))
                .andDo(print())
                .andExpect(view().name("home"))
                .andExpect(status().isOk());
    }

}
