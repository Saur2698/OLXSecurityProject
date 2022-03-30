package com.zensar.olx.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
	// UserDetailsService is an interface given by spring security
	// this interface has only one method loadUser By UserName(String userName)
	// This method is responsible for loading the user object form database
	// if user object couldn't found in database this method should throw userName
	// nt found exception
	// It is responsibility of developer to give implementation of interface

	@Autowired
	private UserDetailsService userDetailsService;

	// following Bean is used for password encoding
	@Bean
	public PasswordEncoder getPasswordEncoder() {
		BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		return passwordEncoder;
	}

	// http: status code 401- specify that user is not passing right username and
	// password

	// Authentication - username, password (biometric)
	// prove whatever user is claiming
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// we are storing credentials in Memory
		// .roles("USER")

		// .and()
		// .withUser("zensar")
		// .password("$2a$10$qYM4NErXn6Sx.jFU4aen2.72FZYANerxlpDI/vkzq8PMDNI6KTFii")
		// //password //this is bad to store password in plain text
		// we must store password in encoded form
		// BCrypt Password Encoder is recommended for password encoding
		auth

				.userDetailsService(userDetailsService)

				.passwordEncoder(getPasswordEncoder())// this line tells spring security to use BCryptPasswordEncoder
		;

	}

	// What are you allowed to do?
	// To use PC, chair

	// to take chairs home
	// Authorization specifying access rights to a resource
	// Access based on Roles

	// http: status code 403(forbidden)- specify user is authenticated but not
	// authorized to this..
	// ..resource

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf()
		.disable()
		.authorizeRequests()
		.antMatchers("/user/authenticate","/token/validate")
		.permitAll()
		.antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
		.anyRequest().authenticated().and()
				.addFilter(new com.zensar.olx.filter.JWTAuthenticationFilter(authenticationManager()))
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // This is MUST for REST we

	}

	@Override
	@Bean
	protected AuthenticationManager authenticationManager() throws Exception {
		return super.authenticationManager();
	}

}
