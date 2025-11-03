package com.security.springsecuritymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


//@EnableWebSecurity
//@Configuration
public class SecurityConfig {

//    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
        AuthenticationManager authenticationManager = builder.build(); // AuthenticationManager 생성
//        AuthenticationManager authenticationManager1 = builder.getObject(); // AuthenticationManager 를 다른 곳에서 사용하기 위한 참조 방법

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/anonymous").hasRole("GUEST")
                        .requestMatchers("/anonymousContext", "/authentication").permitAll()
                        .anyRequest().authenticated())
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
                .rememberMe(rememberMe -> rememberMe
//                        .alwaysRemember(true)
                        .tokenValiditySeconds(3600)
                        .userDetailsService(userDetailsService())
                        .rememberMeParameter("remember")
                        .rememberMeCookieName("remember")
                        .key("security")
                        .anonymous(anonymous -> anonymous
                        .principal("guest") // 사용자 정보
                        .authorities("ROLE_GUEST") // 익명 사용자 권한
                */
                .authenticationManager(authenticationManager)
                .addFilterBefore(customAuthenticationFilter(http, authenticationManager), UsernamePasswordAuthenticationFilter.class);
                /*
                .formLogin(Customizer.withDefaults())
                .logout(logout -> logout
                        .logoutUrl("/logoutProc")
                        .logoutSuccessUrl("/logoutSuccess")
                        .logoutSuccessHandler(new LogoutSuccessHandler() {
                            @Override
                            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                response.sendRedirect("/logoutSuccess");
                            }
                        })
                        .deleteCookies("JSESSIONID", "remember-me") //쿠키 제거
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .addLogoutHandler(new LogoutHandler() {
                            @Override
                            public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                                HttpSession session = request.getSession();
                                session.invalidate();
                                SecurityContextHolder.getContextHolderStrategy().getContext().setAuthentication(null);
                                SecurityContextHolder.getContextHolderStrategy().clearContext();
                            }
                        })
                        .permitAll()
                );
                */

        return http.build();
    }

    public CustomAuthenticationFilter customAuthenticationFilter(HttpSecurity http, AuthenticationManager authenticationManager) {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(http);
        customAuthenticationFilter.setAuthenticationManager(authenticationManager);
        return customAuthenticationFilter;
    }

//    @Bean
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
