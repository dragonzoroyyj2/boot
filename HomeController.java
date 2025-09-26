package com.example.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.security.core.Authentication;

import com.example.demo.jwt.JwtUtil;

@Controller
public class HomeController {

    // 루트 URL → 로그인 페이지로 리다이렉트
    @GetMapping("/")
    public String root() {
        return "redirect:/login";
    }

    // 로그인 페이지
    @GetMapping("/login")
    public String login() {
        return "login"; // login.html
    }

    // 로그인 성공 후 홈 페이지
    @GetMapping("/home")
    public String home(Model model, Authentication authentication) {
        String username = authentication.getName();
        String token = JwtUtil.generateToken(username);

        model.addAttribute("username", username);
        model.addAttribute("jwtToken", token);

        return "home"; // home.html
    }
}
