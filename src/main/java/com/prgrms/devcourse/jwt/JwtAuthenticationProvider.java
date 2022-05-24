package com.prgrms.devcourse.jwt;

import java.util.List;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;

import com.prgrms.devcourse.user.User;
import com.prgrms.devcourse.user.UserService;

public class JwtAuthenticationProvider implements AuthenticationProvider {

	private final Jwt jwt;
	private final UserService userService;

	public JwtAuthenticationProvider(Jwt jwt, UserService userService) {
		this.jwt = jwt;
		this.userService = userService;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken)authentication;
		return processUserAuthentication(
			String.valueOf(jwtAuthenticationToken.getPrincipal()),
			jwtAuthenticationToken.getCredentials()
		);
	}

	private Authentication processUserAuthentication(String principal, String credential) {
		try {
			User user = userService.login(principal, credential);
			List<GrantedAuthority> authorities = user.getGroup().getAuthorities();
			String token = getToken(user.getLoginId(), authorities);
			JwtAuthenticationToken authenticated = new JwtAuthenticationToken(
				new JwtAuthentication(token, user.getLoginId()),
				null,
				authorities
			);
			authenticated.setDetails(user);
			return authenticated;
		} catch (IllegalArgumentException e) {
			throw new BadCredentialsException(e.getMessage());
		} catch (Exception e) {
			throw new AuthenticationServiceException(e.getMessage(), e);
		}
	}

	private String getToken(String loginId, List<GrantedAuthority> authorities) {
		String[] roles = authorities.stream()
			.map(GrantedAuthority::getAuthority)
			.toArray(String[]::new);
		return jwt.sign(Jwt.Claims.from(loginId, roles));
	}
}
