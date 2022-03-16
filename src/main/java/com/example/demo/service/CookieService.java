package com.example.demo.service;

import java.security.NoSuchAlgorithmException;
import java.util.List;

public interface CookieService {

    List<String> generateCookies(final String subject) throws NoSuchAlgorithmException;

    List<String> deleteCookies();

}
