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
	private final AuthenticationManager authenticationManager;

	public UserRestController(UserService userService, AuthenticationManager authenticationManager) {
		this.userService = userService;
		this.authenticationManager = authenticationManager;
	}

	@PostMapping("/user/login")
	public UserDto login(@RequestBody LoginRequest request) {
		JwtAuthenticationToken authToken = new JwtAuthenticationToken(request.getPrincipal(), request.getCredentials());
		Authentication resultToken = authenticationManager.authenticate(authToken);
		JwtAuthenticationToken authenticated = (JwtAuthenticationToken)resultToken;
		JwtAuthentication principal = (JwtAuthentication)authenticated.getPrincipal();
		User user = (User) authenticated.getDetails();
		return new UserDto(principal.token, user.getLoginId(), user.getGroup().getName());
	}

	@GetMapping("/user/me")
	public UserDto me(@AuthenticationPrincipal JwtAuthentication authentication) {
		return userService.findByLoginId(authentication.username)
			.map(user ->
				new UserDto(authentication.token, authentication.username, user.getGroup().getName())
			)
			.orElseThrow(() -> new IllegalArgumentException("Could not found user for " + authentication.username));
	}
}
