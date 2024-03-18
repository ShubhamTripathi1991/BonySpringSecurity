package com.shubham.bonyspringsecurity.jwt;

import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtAuthenticationController {
	
	@PostMapping("/authenticate")
	public Authentication authenticate(Authentication authentication) {
		return authentication;
	}

}
