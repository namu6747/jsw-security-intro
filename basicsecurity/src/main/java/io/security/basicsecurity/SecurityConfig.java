package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
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
            // 모든 요청이 인가되어야 한다.
        http.httpBasic().disable()
                .authorizeRequests()
                .anyRequest().authenticated()
            .and()
                .formLogin()
                    //.loginPage("/loginPage") // 로그인 렌더링 html
                    .defaultSuccessUrl("/") // 로그인 성공 후 이동 페이지
                    .failureUrl("/login?error=true") // 로그인 실패 후 이동
                    .usernameParameter("userId")
                    .passwordParameter("passWd")
                    .loginProcessingUrl("/login_proc") // 로그인 Form Action Url
                    .successHandler(new AuthenticationSuccessHandler() {
                        @Override
                        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                            System.out.println("authentication = " + authentication.getName());
                            response.sendRedirect("/");
                        }})
                    .failureHandler(new AuthenticationFailureHandler() {
                        @Override
                        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                            System.out.println("exception = " + exception.getMessage());
                            response.sendRedirect("/login");
                        }})
                    .permitAll() // 위에서 모든 인가를 요청했지만, 여기에 있는 Url은 허용한다.
            .and()
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
            .and()
                .rememberMe()
                    .rememberMeParameter("remember")
                    .tokenValiditySeconds(3600) // 기본 14일
                    .alwaysRemember(true) // 기능이 활성화되지 않아도 항상 실행
                    .userDetailsService(userDetailsService)
            .and()
                .sessionManagement()
                    .maximumSessions(1) // -1 == 무제한
                    .maxSessionsPreventsLogin(true) // 동시 로그인 차단, false : 기존 세션 만료(default)
                    .expiredUrl("/expired")
            .and()
                .invalidSessionUrl("/invalid")
                .sessionFixation() // 세션 고정 보호
                //servlet 3.1 이상, none(행동x), migrateSession(3.1이하), newSession(설정등이 새로됨)
                .changeSessionId() // none(), migrateSession(), newSession()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // default
        ;

        /*http.antMatcher("/shop/**")
                .authorizeRequests()
                .antMatchers("/shop/login", "/shop/users/**").permitAll()
                .antMatchers("/shop/mypage").hasRole("USER")
                .antMatchers("/shop/admin/pay").access("hasRole('ADMIN)")
                .antMatchers("/shop/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated()
        ;*/

//        http.exceptionHandling()
////                .authenticationEntryPoint(authenticationEntryPoion())
////                .accessDeniedHandler(accessDeniedHandler())
//        ;

//        http.csrf(); // default


    }
}
