package com.prgrms.devcourse.controller;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.prgrms.devcourse.jwt.JwtAuthentication;
import com.prgrms.devcourse.jwt.JwtAuthenticationToken;
import com.prgrms.devcourse.user.LoginRequest;
import com.prgrms.devcourse.user.User;
import com.prgrms.devcourse.user.UserDto;
import com.prgrms.devcourse.user.UserService;

@RequestMapping("/api")
@RestController
public class UserRestController {

	private final UserService userService;

	public UserRestController(UserService userService) {
		this.userService = userService;
	}

	@GetMapping("/user/me")
	public UserDto me(@AuthenticationPrincipal JwtAuthentication authentication) {
		return userService.findByUsername(authentication.username)
			.map(user ->
				new UserDto(authentication.token, authentication.username, user.getGroup().getName())
			)
			.orElseThrow(() -> new IllegalArgumentException("Could not found user for " + authentication.username));
	}
}
