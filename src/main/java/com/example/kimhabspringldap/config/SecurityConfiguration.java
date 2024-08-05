package com.example.kimhabspringldap.config;

import com.example.kimhabspringldap.service.LdapUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final LdapUserService ldapUserService;

    @Autowired
    private JwtRequestFilter jwtRequestFilter;

 //   @Autowired
  //  private CustomUserDetailsService customUserDetailsService;

    public SecurityConfiguration(LdapUserService ldapUserService) {
        this.ldapUserService = ldapUserService;
    }


//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.csrf().disable()
//                .authorizeRequests()
//                .anyRequest().authenticated()
//                .and()
//                .formLogin();
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/auth/**","/swagger-ui/**","/v3/api-docs/**","/ldap/**").permitAll()
                .anyRequest().authenticated()
                .and()
                // Add the JWT filter
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(customUserDetailsService);
//    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.ldapAuthentication()
               // .userDnPatterns()
                .userDnPatterns("uid={0},ou=people") // "uid={0}";
                 // Adjust based on your LDAP structure
                .groupSearchBase("ou=groups") // ou=groups; ""
                .contextSource()
               // .url("ldap://ldap.forumsys.com:389/dc=example,dc=com")
                .url("ldap://localhost:8389/dc=springframework,dc=org")
                .and()
                .passwordCompare()
              //  .passwordEncoder(new BCryptPasswordEncoder())
                .passwordAttribute("userPassword")
               // .managerDn("cn=read-only-admin,dc=example,dc=com")
               // .managerPassword("password")
        ;
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
