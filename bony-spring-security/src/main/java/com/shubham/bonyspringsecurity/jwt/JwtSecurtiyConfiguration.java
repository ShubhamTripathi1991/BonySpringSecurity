package com.shubham.bonyspringsecurity.jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

//@Configuration
public class JwtSecurtiyConfiguration {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

		http.httpBasic();
        http.csrf(csrf -> csrf.disable());
        http.headers(headers -> headers.frameOptions().sameOrigin());
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
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
    
    @Bean
    KeyPair keyPair() {
    	KeyPairGenerator keyPairGenerator;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
	    	return keyPairGenerator.generateKeyPair();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
    	
    }
    
    @Bean
	RSAKey rsaKey(KeyPair keyPair) {
		return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic()).privateKey(keyPair.getPrivate())
				.keyID(UUID.randomUUID().toString()).build();
	}
    
	@Bean
	JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
		var jwkSet = new JWKSet(rsaKey);
//		var jwkSource = new JWKSource() {
//			@Override
//			public List get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
//				return jwkSelector.select(jwkSet);
//			}
//		};
//		return jwkSource;
		return (jwkSelector, context) -> jwkSelector.select(jwkSet);
	}
    
    @Bean
    JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
    	return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build(); 
    }
    
    @Bean
    JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
    	return new NimbusJwtEncoder(jwkSource);
    }
}
