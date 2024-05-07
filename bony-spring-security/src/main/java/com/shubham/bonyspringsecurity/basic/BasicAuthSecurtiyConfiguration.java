package com.shubham.bonyspringsecurity.basic;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
//@EnableGlobalMethodSecurity(
//		  prePostEnabled = true, 
//		  securedEnabled = true, 
//		  jsr250Enabled = true)
@EnableMethodSecurity(securedEnabled = true)
public class BasicAuthSecurtiyConfiguration {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests((requests) -> requests
				.requestMatchers("/users").hasRole("USER")
				.requestMatchers("/admin/**").hasRole("ADMIN")
				.anyRequest().authenticated());
		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

		// http.formLogin();
		http.httpBasic();
        http.csrf(csrf -> csrf.disable());
        http.headers(headers -> headers.frameOptions().sameOrigin());
		return http.build();
	}

    @Bean
    WebMvcConfigurer corsConfigurer() {
		return new WebMvcConfigurer() {
			public void addCorsMappings(CorsRegistry registry) {
				registry.addMapping("/**").allowedMethods("*").allowedOrigins("http://localhost:8080");
			}
		};
	}

//    @Bean
//    UserDetailsService userDetailsService() {
//		var user = User.withUsername("shubham").password("{noop}123").roles("USER").build();
//		var admin = User.withUsername("admin").password("{noop}123").roles("ADMIN").build();
//		return new InMemoryUserDetailsManager(user,admin);
//	}

    @Bean
    DataSource dataSource() {
		return new EmbeddedDatabaseBuilder().setType(EmbeddedDatabaseType.H2)
				.addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION).build();
	}
    
    @Bean
    UserDetailsService userDetailsService(DataSource dataSource) {
		var user = User.withUsername("shubham")
//				.password("{noop}123")
				.password("123")
				.passwordEncoder(str->bCryptPasswordEncoder().encode(str))
				.roles("USER").build();
		var admin = User.withUsername("admin")
//				.password("{noop}123")
				.password("123")
				.passwordEncoder(str->bCryptPasswordEncoder().encode(str))
				.roles("ADMIN","USER").build();
		JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
		jdbcUserDetailsManager.createUser(user);
		jdbcUserDetailsManager.createUser(admin);
		return jdbcUserDetailsManager;
	}
    @Bean
    BCryptPasswordEncoder bCryptPasswordEncoder() {
    	return new BCryptPasswordEncoder();
    }

}
