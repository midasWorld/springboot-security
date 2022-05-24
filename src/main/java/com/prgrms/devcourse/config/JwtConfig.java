package com.prgrms.devcourse.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ToString
@Getter @Setter
@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtConfig {

	private String header;
	private String issuer;
	private String clientSecret;
	private int expirySeconds;
}
