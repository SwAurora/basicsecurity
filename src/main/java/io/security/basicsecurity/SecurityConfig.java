package io.security.basicsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final UserDetailsService userDetailsService;

    public SecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    /*

    // 웹 보안 구성
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // 권한 부여 규칙 ( 모든 요청에 인증된 사용자만 허용)
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/invalid", "/expired")
                        .permitAll()
                        .anyRequest()
                        .authenticated())
                // 로그인
                .formLogin(formLogin -> formLogin
                        //.loginPage("/loginPage")
                        //.defaultSuccessUrl("/")
                        //.failureUrl("/login")
                        .usernameParameter("userId")
                        .passwordParameter("passwd")
                        .loginProcessingUrl("/login_proc")
                        .successHandler((request, response, authentication) -> {
                            System.out.println("authentication" + authentication.getName());
                            response.sendRedirect("/");
                        })
                        .failureHandler((request, response, exception) -> {
                            System.out.println("exception" + exception.getMessage());
                            response.sendRedirect("/login");
                        })
                        .permitAll())
                // 로그아웃
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login")
                        .addLogoutHandler((request, response, authentication) -> {
                            HttpSession session = request.getSession();
                            session.invalidate();
                        })
                        .logoutSuccessHandler((request, response, authentication) -> {
                            System.out.println("authentication");
                            response.sendRedirect("/login");
                        })
                        .deleteCookies("remember-me"))
                // 자동 로그인
                .rememberMe(rememberMe -> rememberMe
                        .rememberMeParameter("remember") // 기본 파라미터명은 remember-me
                        .tokenValiditySeconds(3600) // Default 14일
//                        .alwaysRemember(true) // 리멤버 미 기능이 활성화되지 않아도 항상 실행
                        .userDetailsService(userDetailsService))
                .sessionManagement(sessionMng -> sessionMng
                        // 세션 고정 보호
//                        .sessionFixation().changeSessionId() // 기본 값
//                        .sessionFixation().none() // 로그인 해도 세션ID가 바뀌지 않음
                        // 세션 정책
                        .sessionCreationPolicy(SessionCreationPolicy.ALWAYS) // 항상 세션 생성
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // 필요시 생성 (기본값)
                        .sessionCreationPolicy(SessionCreationPolicy.NEVER) // 생성하진 않지만 이미 존재하면 사용
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 생성하지 않고 존재해도 사용하지 않음
                        // 동시 세션 제어
                        .invalidSessionUrl("/invalid") // 세션이 유효하지 않을 때 이동 할 페이지 expiredUrl보다 우선
                        .maximumSessions(1) // -1 : 무제한 로그인 세션 허용
                        .maxSessionsPreventsLogin(false) // default는 false, true로 하면 뒷사용자 로그인 실패
                        .expiredUrl("/expired") // 세션이 만료된 경우 이동 할 페이지
                );

        return http.build();
    }

    */

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorizeHttpRequests -> {
                    authorizeHttpRequests
                            .requestMatchers("/user").hasRole("USER")
                            .requestMatchers("/admin/pay").hasRole("ADMIN")
//                            .requestMatchers("/admin/**").access(new WebExpressionAuthorizationManager("hasRole('ADMIN') or hasRole('SYS')"))
                            .requestMatchers("/admin/**").hasRole("SYS")
                            .anyRequest()
                            .authenticated();
                });

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");
        return auth.build();
    }
}
