package com.example.kimhabspringldap.controller;

import com.example.kimhabspringldap.service.LdapUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("ldap")
public class LdapController {

    @Autowired
    private LdapUserService ldapUserService;

    @GetMapping("/users")
    public List<Map<String, Object>> getAllUsers() {
        return ldapUserService.getAllUsers();
    }

    @GetMapping("/find")
    public Map<String, Object> find(@RequestParam String username) {
      // return ldapUserService.findByUsername(username).get(0);
       return ldapUserService.findByUsername1(username);
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        boolean isAuthenticated = ldapUserService.authenticate(username, password);
        if (isAuthenticated) {
            return "Login successful!";
        } else {
            return "Bad credentials!";
        }
    }

}

