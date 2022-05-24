package com.prgrms.devcourse.user;

import lombok.Getter;
import lombok.ToString;

@ToString
@Getter
public class LoginRequest {

	private String principal;

	private String credentials;

	protected  LoginRequest() {}

	public LoginRequest(String principal, String credentials) {
		this.principal = principal;
		this.credentials = credentials;
	}
}
