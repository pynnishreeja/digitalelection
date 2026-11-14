package com.election.auditservice.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.election.auditservice.security.InternalServiceAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Bean
    public InternalServiceAuthenticationFilter internalServiceAuthenticationFilter(
            @Value("${internal.service.token}") String internalServiceToken) {
        return new InternalServiceAuthenticationFilter(internalServiceToken);
    }

    @Bean
    public org.springframework.boot.web.servlet.FilterRegistrationBean<InternalServiceAuthenticationFilter>
            internalServiceFilterRegistration(InternalServiceAuthenticationFilter filter) {
        var registration = new org.springframework.boot.web.servlet.FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            InternalServiceAuthenticationFilter internalServiceAuthenticationFilter)
            throws Exception {

        http
            .csrf(csrf -> csrf.disable())
            .formLogin(form -> form.disable())
            .httpBasic(basic -> basic.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.POST, "/api/audit").hasRole("SERVICE")
                .anyRequest().permitAll()
            )
            .addFilterBefore(internalServiceAuthenticationFilter,
                    UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}