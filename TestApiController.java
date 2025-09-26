package com.example.demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class TestApiController {

    @GetMapping("/secure")
    public String secureEndpoint() {
        return "🔒 This is a secured API with JWT!";
    }

    @GetMapping("/public/hello")
    public String publicEndpoint() {
        return "🌐 This is a public API (no auth needed).";
    }
}
