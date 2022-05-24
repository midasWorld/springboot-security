package com.prgrms.devcourse.jwt;

import static com.google.common.base.Preconditions.*;
import static org.apache.commons.lang3.StringUtils.*;

import lombok.ToString;

public class JwtAuthentication {

	public final String token;

	public final String username;

	public JwtAuthentication(String token, String username) {
		checkArgument(isNotEmpty(token), "token must be provided.");
		checkArgument(isNotEmpty(username), "username must be provided.");

		this.token = token;
		this.username = username;
	}
}
