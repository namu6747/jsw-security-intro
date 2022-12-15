package io.security.basicsecuritynew;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http
            .authorizeRequests()
               .anyRequest().authenticated() // 어떤 요청에도 인증을 받겠다.
            .and()
                .formLogin() // formLogin 방식으로 인증하겠다.
        ;

        http.httpBasic();

        return http.build();
    }
}
