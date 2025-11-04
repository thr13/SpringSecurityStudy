package com.security.springsecuritymaster;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class CustomUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 여기서 검증을 수행해도 된다!!
        return User.withUsername("user")
                .password("{noop}1111")
                .roles("USER")
                .build();
    }
}
