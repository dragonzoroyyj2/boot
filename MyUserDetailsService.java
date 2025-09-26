package com.example.demo.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // ✅ 테스트 계정: 아이디 testuser / 비번 password
        if ("testuser".equals(username)) {
            String encodedPassword = new BCryptPasswordEncoder().encode("password");
            return new User("testuser", encodedPassword, Collections.emptyList());
        }
        throw new UsernameNotFoundException("User not found: " + username);
    }
}
