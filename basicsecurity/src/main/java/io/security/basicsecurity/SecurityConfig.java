package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
            .anyRequest().authenticated()
            .and()
            .formLogin();

        http.httpBasic().disable();

        http.formLogin()
                .loginPage("/login.html") // 로그인 렌더링 html
                .defaultSuccessUrl("/home") // 로그인 성공 후 이동 페이지
                .failureUrl("/login.html?error=true") // 로그인 실패 후 이동
                .usernameParameter("username")
                .passwordParameter("password")
                .loginProcessingUrl("/login") // 로그인 Form Action Url
//                .successHandler(loginSuccessHandler())
//                .failureHandler(loginFailureHandler())
                ;

        http.logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                .deleteCookies("JSESSIONID","remember")
//                .addLogoutHandler(logoutHandler())
//                .logoutSuccessHandler(logoutSuccessHandler())
        ;

        http.rememberMe()
                .rememberMeParameter("remember")
                .tokenValiditySeconds(3600) // 기본 14일
                .alwaysRemember(true) // 기능이 활성화되지 않아도 항상 실행
                .userDetailsService(userDetailsService())
        ;

        http.sessionManagement()
                .maximumSessions(1) // -1 == 무제한
                .maxSessionsPreventsLogin(true) // 동시 로그인 차단, false : 기존 세션 만료(default)
                    .expiredUrl("/expired")
                .and()
                .invalidSessionUrl("/invalid")
                .sessionFixation()
                .changeSessionId() // none, migrateSession, new Session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // default
        ;

        http.antMatcher("/shop/**")
                .authorizeRequests()
                .antMatchers("/shop/login", "/shop/users/**").permitAll()
                .antMatchers("/shop/mypage").hasRole("USER")
                .antMatchers("/shop/admin/pay").access("hasRole('ADMIN)")
                .antMatchers("/shop/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated()
        ;

        http.exceptionHandling()
//                .authenticationEntryPoint(authenticationEntryPoion())
//                .accessDeniedHandler(accessDeniedHandler())
        ;

        http.csrf(); // default


    }
}
