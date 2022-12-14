package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
class SecurityConfig2 extends WebSecurityConfigurerAdapter{
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().permitAll()
                .and()
                .formLogin();
    }
}

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    protected void configure(HttpSecurity http) throws Exception {
//       http.antMatcher("/**").authorizeRequests().antMatchers("/**").permitAll();

//        httpBasic(http);
//        authorize(http);
//        formLogin(http);
//        logout(http);
//        rememberMe(http);
//        sessionManagement(http);

        //authorizeV2(http);
        //exceptionHandle(http);
//        csrf(http);

//        exTranslate(http);
        multiConfig(http);
        securityContextHolderThreadLocalStrategy();
    }

    private static void securityContextHolderThreadLocalStrategy() {
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_THREADLOCAL);
    }

    private void multiConfig(HttpSecurity http) throws Exception{
        http.antMatcher("/admin/**")
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .httpBasic();
    }

    private void exTranslate(HttpSecurity http) throws Exception{
        http.authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();

        http.formLogin()
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(request, response); // ???????????? ????????????.
                        String redirectUrl = savedRequest.getRedirectUrl();
                        System.out.println("redirectUrl = " + redirectUrl);
                        response.sendRedirect(redirectUrl);
                    }
                })
        ;

        http.exceptionHandling()
//                .authenticationEntryPoint(new AuthenticationEntryPoint() { // ?????? ??????
//                    @Override
//                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//                        String requestUrl = request.getRequestURL().toString();
//                        System.out.println("authentication failed : requestUrl = " + requestUrl);
//                        response.sendRedirect("/login"); // ?????????????????? ???????????? ????????????????????? ?????????
//                    }
//                })
                .accessDeniedHandler(new AccessDeniedHandler() { // ?????? ??????
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        String requestUrl = request.getRequestURL().toString();
                        System.out.println("access denied : requestUrl = " + requestUrl);
                        response.sendRedirect("/denied");
                    }
                })
                ;
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
        http.antMatcher("/shop/**") // ?????? ????????? ?????? ?????? ??????
                .authorizeRequests() // ????????? ?????? ?????? ??????
                .antMatchers("/shop/login", "/shop/users/**").permitAll() // ????????? ????????? ????????????.
                .antMatchers("/shop/mypage").hasRole("USER") // uSER ????????? ??????
                .antMatchers("/shop/admin/pay").access("hasRole('ADMIN')")
                .antMatchers("/shop/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated() // ????????? ?????? ????????? ???????????? ????????? ???????????? ????????????.
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
                    //.loginPage("/loginPage") // ????????? ????????? html
                    .defaultSuccessUrl("/") // ????????? ?????? ??? ?????? ?????????
                    .failureUrl("/login?error") // ????????? ?????? ??? ??????
                    .usernameParameter("username")
                    .passwordParameter("password")
                    //.loginProcessingUrl("/login_proc") // ????????? Form Action Url
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
                    .permitAll(); // ????????? ?????? ????????? ???????????????, ????????? ?????? Url??? ????????????.;
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
                .maximumSessions(-1) // -1 == ?????????
                .maxSessionsPreventsLogin(true) // ?????? ????????? ??????, false : ?????? ?????? ??????(default)
                .expiredUrl("/expired")
                .and()
                .invalidSessionUrl("/invalid")
                .sessionFixation() // ?????? ?????? ??????
                //servlet 3.1 ??????, none(??????x), migrateSession(3.1??????), newSession(???????????? ?????????)
                .changeSessionId() // none(), migrateSession(), newSession()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED); // default

    }

    private void rememberMe(HttpSecurity http) throws Exception {
        http.rememberMe()
                            .rememberMeParameter("remember")
                            .tokenValiditySeconds(3600) // ?????? 14???
                            .alwaysRemember(false) // ????????? ??????????????? ????????? ?????? ??????
                            .userDetailsService(userDetailsService);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");
    }
}
