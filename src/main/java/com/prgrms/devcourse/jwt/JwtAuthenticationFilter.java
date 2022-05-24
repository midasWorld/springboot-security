package com.prgrms.devcourse.jwt;

import static java.util.Collections.*;
import static java.util.stream.Collectors.*;
import static org.apache.commons.lang3.StringUtils.*;

import java.io.IOException;
import java.net.URLDecoder;
import java.util.Arrays;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.GenericFilterBean;

import com.auth0.jwt.exceptions.JWTVerificationException;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JwtAuthenticationFilter extends GenericFilterBean {

	private final String headerKey;
	private final Jwt jwt;

	public JwtAuthenticationFilter(String headerKey, Jwt jwt) {
		this.headerKey = headerKey;
		this.jwt = jwt;
	}

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
		/**
		 - JWT 필터 (JwtAuthenticationFilter) 만들어보기
		 - HTTP 요청 헤더에서 JWT 토큰이 있는지 확인
		 - JWT 토큰에서 username, roles을 추출하여 UsernamePasswordAuthenticationToken을 생성
		 - 앞서 만든 UsernamePasswordAuthenticationToken를 SecurityContext에 넣어줌
		 - JWT 필터를 Spring Security 필터 체인에 추가 (어디에 추가하면 좋을지 고민)
		 - 필터를 추가한 후 HTTP 요청에 JWT 토큰을 추가하면, GET /api/user/me API 호출이 성공해야 함
		 - UserRestControllerTest 테스트를 통과해야 함
		 */
		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;

		if (SecurityContextHolder.getContext().getAuthentication() == null) {
			String token = getToken(request);
			if (token != null) {
				try {
					Jwt.Claims claims = verify(token);
					log.debug("Jwt parse result: {}", claims);

					String username = claims.username;
					List<GrantedAuthority> authorities = getAuthorities(claims);

					if (isNotEmpty(username) && authorities.size() > 0) {
						JwtAuthenticationToken authentication
							= new JwtAuthenticationToken(new JwtAuthentication(token, username), null, authorities);
						authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
						SecurityContextHolder.getContext().setAuthentication(authentication);
					}
				} catch (JWTVerificationException e) {
					log.warn("Jwt processing failed: {}", e.getMessage());
				}

			}
		} else {
			log.debug("SecurityContextHolder not populated with security token, as it already contained: {}",
				SecurityContextHolder.getContext().getAuthentication()
			);
		}

		chain.doFilter(request, response);
	}

	private String getToken(HttpServletRequest request) {
		String token = request.getHeader(headerKey);
		if (isNotEmpty(token)) {
			log.debug("Jwt token detected: {}", token);
			try {
				return URLDecoder.decode(token, "UTF-8");
			} catch (Exception e) {
				log.error(e.getMessage(), e);
			}
		}
		return null;
	}

	private Jwt.Claims verify(String token) {
		return jwt.verify(token);
	}

	private List<GrantedAuthority> getAuthorities(Jwt.Claims claims) {
		String[] roles = claims.roles;
		return roles == null || roles.length == 0
			? emptyList()
			: Arrays.stream(roles).map(SimpleGrantedAuthority::new).collect(toList());
	}
}
