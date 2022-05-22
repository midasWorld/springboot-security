package com.prgrms.devcourse.config;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
				.withUser("user").password("{noop}user123").roles("USER")
				.and()
				.withUser("admin01").password("{noop}admin123").roles("ADMIN")
				.and()
				.withUser("admin02").password("{noop}admin123").roles("ADMIN")
		;
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/assets/**");
	}

	@Bean
	public AccessDeniedHandler accessDeniedHandler() {
		return (request, response, e) -> {
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			Object principal = authentication != null ? authentication.getPrincipal() : null;
			log.warn("{} is denied", principal, e);
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			response.setContentType("text/plain");          // 평문을 리턴
			response.getWriter().write("## ACCESS DENIED ##");
			response.getWriter().flush();
			response.getWriter().close();
		};
	}

	public SecurityExpressionHandler<FilterInvocation> securityExceptionHandler() {
		return new CustomWebSecurityExpressionHandler(
				new AuthenticationTrustResolverImpl(),
				"ROLE_"
		);
	}

	@Bean
	public AccessDecisionManager accessDecisionManager() {
		List<AccessDecisionVoter<?>> voters = new ArrayList<>();
		voters.add(new WebExpressionVoter());
		voters.add(new OddAdminVoter(new AntPathRequestMatcher("/admin")));
		return new UnanimousBased(voters);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.authorizeRequests()
					.accessDecisionManager(accessDecisionManager())
					.antMatchers("/me").hasAnyRole("USER", "ADMIN")
					.antMatchers("/admin").access("isFullyAuthenticated() and hasRole('ADMIN')")
					.anyRequest().permitAll()
					.and()
				.formLogin()
					.defaultSuccessUrl("/")
					.permitAll()
					.and()
				.logout()
					.logoutUrl("/logout")
					.logoutSuccessUrl("/")
					.and()
				.rememberMe()
					.rememberMeParameter("remember-me")
					.tokenValiditySeconds(300)
					.and()
				/**
				 * HTTP 요청을 HTTPS 요청으로 리다이렉트
				 */
				// .requiresChannel()
				// 	.anyRequest().requiresSecure()
				// 	.and()
				.anonymous()
					.principal("thisIsAnonymousUser")
					.authorities("ROLE_ANONYMOUS", "ROLE_UNKNOWN")
					.and()
				.exceptionHandling()
					.accessDeniedHandler(accessDeniedHandler())
					.and()
				.sessionManagement()
					.sessionFixation().changeSessionId()
					.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
					.invalidSessionUrl("/")
					.maximumSessions(1)
					.maxSessionsPreventsLogin(false)
					.and()
		;
	}
}
