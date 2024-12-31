package com.webshop.user.controller;

import com.webshop.user.model.User;
import com.webshop.user.repository.UserRepository;
import com.webshop.user.security.JwtUtil;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    public UserController(UserRepository userRepository, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public Map<String, String> loginUser(@RequestBody User user) {
        User foundUser = userRepository.findByUsername(user.getUsername());
        if (foundUser != null && foundUser.getPassword().equals(user.getPassword())) {
            String accessToken = jwtUtil.generateAccessToken(foundUser);
            String refreshToken = jwtUtil.generateRefreshToken(foundUser);

            Map<String, String> tokens = new HashMap<>();
            tokens.put("accessToken", accessToken);
            tokens.put("refreshToken", refreshToken);
            return tokens;
        }
        throw new RuntimeException("Invalid credentials");
    }

    @PostMapping("/refresh")
    public Map<String, String> refreshAccessToken(@RequestHeader("Authorization") String refreshToken) {
        refreshToken = refreshToken.substring(7);  // Remove "Bearer "
        Claims claims = jwtUtil.extractClaims(refreshToken);

        if (claims != null && !jwtUtil.isTokenExpired(refreshToken)) {
            String username = claims.getSubject();
            User user = userRepository.findByUsername(username);

            String newAccessToken = jwtUtil.generateAccessToken(user);

            Map<String, String> tokens = new HashMap<>();
            tokens.put("accessToken", newAccessToken);
            tokens.put("refreshToken", refreshToken);  // Refresh token remains the same
            return tokens;
        }
        throw new RuntimeException("Invalid or expired refresh token");
    }
}

