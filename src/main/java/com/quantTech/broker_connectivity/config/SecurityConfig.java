package com.quantTech.broker_connectivity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import static org.springframework.security.config.Customizer.withDefaults;


@Configuration
public class SecurityConfig {

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		
		// 1) All requests should be authenticated
		http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
		
		// 2) If the user is not authenticated, redirect them to the login page
		http.httpBasic(withDefaults());
			
		// 3) CSRF protection is enabled by default make it disabled for simplicity
		http.csrf(csrf -> csrf.disable());
		
		return http.build();
	}
}