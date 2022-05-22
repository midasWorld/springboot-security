package com.prgrms.devcourse.config;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class AuthenticationEvents {

	@EventListener
	public void handleAuthenticationSuccessEvent(AuthenticationSuccessEvent event) {
		Authentication authentication = event.getAuthentication();
		log.info("Successful authentication result: {}", authentication.getPrincipal());
	}

	@EventListener
	public void handleAuthenticationFailureEvent(AbstractAuthenticationFailureEvent event) {
		Exception e = event.getException();
		Authentication authentication = event.getAuthentication();
		log.warn("Unsuccessful authentication result: {}", authentication, e);
	}
}
