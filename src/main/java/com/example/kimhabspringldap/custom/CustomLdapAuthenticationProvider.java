package com.example.kimhabspringldap.custom;

import com.example.kimhabspringldap.service.LdapUserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
@Slf4j
public class CustomLdapAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private LdapUserService ldapUserService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        // Step 1: Search for the user to get usrname
        Map<String, Object> ldapUser = ldapUserService.findByUsername(username).get(0);
        if (ldapUser.isEmpty()) {
            throw new UsernameNotFoundException("User not found: " + username);
        }

        // Step 2: Attempt to bind with the found DN and provided password
        try {

            var isAuth = ldapUserService.authenticate(username, password);
            if (!isAuth) throw new BadCredentialsException(super.toString());

            // authorities
            List<String> groupsByUid = ldapUserService.getGroupsByUid(username);
            log.info("custom authenticate with authority : {}", groupsByUid);
            return new UsernamePasswordAuthenticationToken(username, password, groupsByUid.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
        } catch (Exception e) {
            throw new AuthenticationException("Authentication failed for user: " + username, e) {
            };
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
