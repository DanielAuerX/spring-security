package com.amigoscode.security.config;

import com.amigoscode.security.dao.UserDao;
import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor //lombok  -> not injected (?) through the constructor
public class SecurityConfig {
    private final JwtAthFilter jwtAuthFilter;
    private final UserDao userDao;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http//authorizeRequests().anyRequest().authenticated().and().httpBasic();
                .csrf().disable()
                .authorizeHttpRequests() //.authorizeRequests() min 1:25
                .requestMatchers("/*/*/auth/**")   //.antMatchers("/**/auth/**")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider())  // use self-made authentication provider
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);  //default filter
        //http.formLogin();
        //http.httpBasic();
        return http.build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        final DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());   //use our implementation
        authenticationProvider.setPasswordEncoder(passwordEncoder());  //mandatory to say wich password encoder is to be used; encrypted or not
        return authenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance(); //doesnt do anything (no encryption), not for production
        //return new BCryptPasswordEncoder();  //encrypts the password (pw variables have to be encrypted also)
    }

    @Bean
    public UserDetailsService userDetailsService(){
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
                return userDao.findUserByEmail(email);                // ask database for user credentials; here hard coded
            }
        };
    }

    //can be replaced with a lambda
    /*
        @Bean
    public UserDetailsService userDetailsService(){
        return email -> {
            return APPLICATION_USER
                    .stream()
                    .filter(u -> u.getUsername().equals(email))
                    .findFirst()
                    .orElseThrow(() -> new UsernameNotFoundException("Email was not found!"));                // ask database for user credentials; here hard coded
        };
    }
     */



}
