package com.example.demo.repository;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserRepository {

    private static final List<UserDao> USERS = new ArrayList<>();

    public UserRepository(final PasswordEncoder passwordEncoder) {
        USERS.add(new UserDao("admin", passwordEncoder.encode("admin")));
        USERS.add(new UserDao("user", passwordEncoder.encode("password")));
    }

    public UserDao findByLogin(final String login) {
        return USERS.stream().filter(userDao -> userDao.login().equals(login)).findFirst()
                .orElse(null);
    }

}

