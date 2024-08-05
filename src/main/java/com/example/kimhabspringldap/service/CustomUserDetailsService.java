package com.example.kimhabspringldap.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    private LdapUserService ldapUserService;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        var userLdap = ldapUserService.findByUsername1(username);
        if (!userLdap.isEmpty()) {
            var userDetail = new User(userLdap.get("uid").toString(), userLdap.get("userPassword").toString(), buildUserAuthority(username));
            log.info("userDetail: {} ", userDetail);
            return userDetail;
        }
        throw new UsernameNotFoundException("");
    }

    public Collection<? extends GrantedAuthority> buildUserAuthority(String username) {
        List<String> groupsByUid = ldapUserService.getGroupsByUid(username);
        Set<GrantedAuthority> grantedAuthoritySet = groupsByUid.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
        return grantedAuthoritySet;
    }

}