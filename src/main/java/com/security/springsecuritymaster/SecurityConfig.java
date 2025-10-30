package com.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                /*.formLogin(form -> form
                        .loginPage("/loginPage") // 로그인 페이지 URL
                        .loginProcessingUrl("/loginProc") // 아이디, 비밀번호 검증 (로그인 요청 시점, 인증 전) URL
                        .defaultSuccessUrl("/", true) // 로그인 성공 후 사용자가 이동할 URL, alwaysUse 값이 true 일 경우 로그인 성공시 무조건 defaultSuccessUrl 이 설정한 URL 로 이동하게 된다 (false 일 경우, 인증에 성공시 이전 위치로 redirect 된다)
                        .failureUrl("/failed") // 인증에 실패할 경우 사용자가 이동할 URL
                        .usernameParameter("userId") // 인증에 아이디를 확인하는 HTTP 매개변수 설정(기본값: username)
                        .passwordParameter("passwd") // 인증에 비밀번호를 확인하는 HTTP 매개변수(기본값: password)
                        .successHandler((request, response, authentication) -> {
                            System.out.println("authentication: " + authentication);
                            response.sendRedirect("/home"); // 인증 성공시 이동할 URL
                        })
                        .failureHandler((request, response, exception) -> {
                            System.out.println("exception: " + exception.getMessage()); // 인증이 실패할 경우 AuthenticationException 이 발생한다
                            response.sendRedirect("/login"); // 인증 실패시 이동할 URL
                        })
                        .permitAll()
                .httpBasic(basic -> basic.authenticationEntryPoint(new CustomAuthenticationEntryPoint())
                )
                */
                .formLogin(Customizer.withDefaults())
                .rememberMe(rememberMe -> rememberMe
//                        .alwaysRemember(true)
                        .tokenValiditySeconds(3600)
                        .userDetailsService(userDetailsService())
                        .rememberMeParameter("remember")
                        .rememberMeCookieName("remember")
                        .key("security")
                );
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user")
                .password("{noop}1111")
                .roles("USER").build();

        UserDetails user2 = User.withUsername("user2")
                .password("{noop}1111")
                .roles("USER").build();

        UserDetails user3 = User.withUsername("user3")
                .password("{noop}1111")
                .roles("USER").build();

        return new InMemoryUserDetailsManager(user);
    }
}
