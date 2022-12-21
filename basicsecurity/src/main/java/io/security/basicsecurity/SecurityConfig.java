package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.SessionManagementFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    protected void configure(HttpSecurity http) throws Exception {
        httpBasic(http);
        authorize(http);
        formLogin(http);
        logout(http);
        rememberMe(http);
        sessionManagement(http);
        //authorizeV2(http);
        //exceptionHandle(http);
        //csrf(http);
    }

    private void csrf(HttpSecurity http) throws Exception {
        http.csrf(); // default
    }

    private void exceptionHandle(HttpSecurity http) throws Exception {
        http.exceptionHandling()
                .authenticationEntryPoint(new AuthenticationEntryPoint() {
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        response.sendRedirect("/?authenticationEntryPoint");
                    }
                })
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/?accessDeniedHandler");
                    }
                })
        ;
    }

    private void authorizeV2(HttpSecurity http) throws Exception {
        http.antMatcher("/shop/**") // 해당 경로에 대한 설정 시작
            .authorizeRequests() // 인가에 대한 설정 시작
                .antMatchers("/shop/login", "/shop/users/**").permitAll() // 여기엔 무조건 허용한다.
                .antMatchers("/shop/mypage").hasRole("USER") // uSER 권한이 필요
                .antMatchers("/shop/admin/pay").access("hasRole('ADMIN')")
                .antMatchers("/shop/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated() // 이외의 모든 요청에 대해서는 권한을 가져야만 허용한다.
    ;
    }

    private void authorize(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/").permitAll()
        ;
        http
                .authorizeRequests()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
        ;
        http
                .authorizeRequests()
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
        ;
    }

    private void httpBasic(HttpSecurity http) throws Exception {
        http.httpBasic().disable();
    }

    private void formLogin(HttpSecurity http) throws Exception {
        http
                .formLogin()
                    //.loginPage("/loginPage") // 로그인 렌더링 html
                    .defaultSuccessUrl("/") // 로그인 성공 후 이동 페이지
                    .failureUrl("/login?error") // 로그인 실패 후 이동
                    .usernameParameter("username")
                    .passwordParameter("password")
                    //.loginProcessingUrl("/login_proc") // 로그인 Form Action Url
                    .successHandler(new AuthenticationSuccessHandler() {
                        @Override
                        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                            System.out.println("authentication = " + authentication.getName());
                            response.sendRedirect("/?successHandler");
                        }})
                    .failureHandler(new AuthenticationFailureHandler() {
                        @Override
                        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                            System.out.println("exception = " + exception.getMessage());
                            response.sendRedirect("/?failureHandler");
                        }})
                    .permitAll(); // 위에서 모든 인가를 요청했지만, 여기에 있는 Url은 허용한다.;
    }

    private void logout(HttpSecurity http) throws Exception {
        http
        .logout()
            .logoutUrl("/logout")
            .logoutSuccessUrl("/login")
            .deleteCookies("JSESSIONID","remember")
            .addLogoutHandler(new LogoutHandler() {
                @Override
                 public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                    HttpSession session = request.getSession();
                    session.invalidate();
             }})
            .logoutSuccessHandler(new LogoutSuccessHandler() {
                @Override
                public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                    response.sendRedirect("/login");
                }})
        ;
    }

    private SessionManagementConfigurer<HttpSecurity> sessionManagement(HttpSecurity http) throws Exception {
        return http.sessionManagement()
                .maximumSessions(-1) // -1 == 무제한
                .maxSessionsPreventsLogin(true) // 동시 로그인 차단, false : 기존 세션 만료(default)
                .expiredUrl("/expired")
                .and()
                .invalidSessionUrl("/invalid")
                .sessionFixation() // 세션 고정 보호
                //servlet 3.1 이상, none(행동x), migrateSession(3.1이하), newSession(설정등이 새로됨)
                .changeSessionId() // none(), migrateSession(), newSession()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED); // default

    }

    private void rememberMe(HttpSecurity http) throws Exception {
        http.rememberMe()
                            .rememberMeParameter("remember")
                            .tokenValiditySeconds(3600) // 기본 14일
                            .alwaysRemember(false) // 기능이 활성화되지 않아도 항상 실행
                            .userDetailsService(userDetailsService);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");
    }
}
