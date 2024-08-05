package com.example.kimhabspringldap.controller;

import com.example.kimhabspringldap.config.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@Slf4j
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    private Map<String, Object> response = new HashMap<>();

    @PostMapping("/login")
    public Object login(@RequestParam String username, @RequestParam String password) {

        try {
            // Authenticate the user
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

            // If authentication is successful, generate a token
            if (authentication.isAuthenticated()) {
                response.put("accessToken", jwtUtil.generateToken(username));
                return response;
            } else {
                throw new RuntimeException("Authentication failed");
            }
        } catch (AuthenticationException e) {
            log.error(e.getMessage());
            throw new RuntimeException("Bad credentials");
        }
    }

    @GetMapping("/user-detail")
    public Object getUserDetail() {
        try {
            var auth = SecurityContextHolder.getContext().getAuthentication();
            var principal = auth.getPrincipal();
            UserDetails userDetails = (UserDetails) principal;
            log.info("userDetails: {}", userDetails);
            return userDetails;
        } catch (Exception e){
            log.error(e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }

    }

}
