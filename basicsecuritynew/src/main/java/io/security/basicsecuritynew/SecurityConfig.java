package io.security.basicsecuritynew;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.annotation.PostConstruct;
import java.util.Arrays;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        // 궁금한곳에 점을 다 찍어 벌레를 눌러
        http
            .authorizeRequests()
               .anyRequest().authenticated() // 어떤 요청에도 인증을 받겠다.
            .and()
                .formLogin(Customizer.withDefaults()) // formLogin 방식으로 인증하겠다.
        ;

        http.httpBasic(Customizer.withDefaults());

        return http.build();
    }

    ;

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user")
                .password(("user"))
                .roles("USER")
                .and()
                .withUser("admin")
                .password(("admin"))
                .roles("USER","ADMIN")
        ;
    }

//    @Bean
    public UserDetailsService userDetailsServiceV1() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withDefaultPasswordEncoder().username("user").password("password").roles("USER").build());
        return manager;
    }

    @Bean
    public UserDetailsService userDetailsService(){
        PasswordEncoder encoder = passwordEncoder();
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        UserDetails user1 = User.withUsername("user").password(encoder.encode("user")).roles("USER").build(); // 비밀번호와 역할까지 작성해줘야 오류가 안나구나
        UserDetails user = User.builder().username("admin").password(encoder.encode("admin")).roles("ADMIN").build();
        manager.createUser(user1);
        return  manager;
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


}
