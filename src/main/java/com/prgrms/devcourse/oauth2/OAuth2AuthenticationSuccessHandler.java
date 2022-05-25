package com.prgrms.devcourse.oauth2;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import com.prgrms.devcourse.jwt.Jwt;
import com.prgrms.devcourse.user.User;
import com.prgrms.devcourse.user.UserService;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

	private final Jwt jwt;
	private final UserService userService;

	public OAuth2AuthenticationSuccessHandler(Jwt jwt, UserService userService) {
		this.jwt = jwt;
		this.userService = userService;
	}

	@Override
	public void onAuthenticationSuccess(
		HttpServletRequest request,
		HttpServletResponse response,
		Authentication authentication
	) throws ServletException, IOException {

		if (authentication instanceof OAuth2AuthenticationToken) {
			OAuth2AuthenticationToken oauth2Token = (OAuth2AuthenticationToken)authentication;
			OAuth2User oauth2User = oauth2Token.getPrincipal();
			String provider = oauth2Token.getAuthorizedClientRegistrationId();
			User user = processUserOAuth2UserJoin(oauth2User, provider);
			String loginSuccessJson = generateToken(user);
			response.setContentType("application/json;charset=UTF-8");
			response.setContentLength(loginSuccessJson.getBytes(StandardCharsets.UTF_8).length);
			response.getWriter().write(loginSuccessJson);
		} else {
			super.onAuthenticationSuccess(request, response, authentication);
		}
	}

	private User processUserOAuth2UserJoin(OAuth2User oauth2User, String provider) {
		return userService.join(oauth2User, provider);
	}

	private String generateLoginSuccessJson(User user) {
		String token = generateToken(user);
		log.debug("Jwt({}) created for oauth2 login user {}", token, user.getUsername());
		return "{\"token\":\"" + token + "\", \"username\":\"" + user.getUsername() + "\", \"group\":\"" + user.getGroup().getName() + "\"}";
	}

	private String generateToken(User user) {
		return jwt.sign(Jwt.Claims.from(user.getUsername(), new String[]{"ROLE_USER"}));
	}
}
