package com.prgrms.devcourse.controller;

import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.prgrms.devcourse.jwt.Jwt;
import com.prgrms.devcourse.user.UserService;

@RequestMapping("/api")
@RestController
public class UserRestController {

	private final Jwt jwt;
	private final UserService userService;

	public UserRestController(Jwt jwt, UserService userService) {
		this.jwt = jwt;
		this.userService = userService;
	}

	@GetMapping("/user/me")
	public String me() {
		return (String)SecurityContextHolder
			.getContext()
			.getAuthentication()
			.getPrincipal();
	}

	@GetMapping("/user/{username}/token")
	public String getToken(@PathVariable String username) {
		UserDetails userDetails = userService.loadUserByUsername(username);
		String[] roles = userDetails.getAuthorities().stream()
			.map(GrantedAuthority::getAuthority)
			.toArray(String[]::new);
		return jwt.sign(Jwt.Claims.from(userDetails.getUsername(), roles));
	}

	@GetMapping("/user/token/verify")
	public Map<String, Object> verify(@RequestHeader("token") String token) {
		return jwt.verify(token).asMap();
	}
}
