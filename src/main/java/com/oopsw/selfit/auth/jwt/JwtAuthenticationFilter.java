package com.oopsw.selfit.auth.jwt;

import java.io.IOException;
import java.util.Map;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.oopsw.selfit.auth.service.CustomOAuth2UserService;
import com.oopsw.selfit.auth.user.CustomOAuth2User;
import com.oopsw.selfit.dto.Member;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager authenticationManager;
	private final CustomOAuth2UserService customOAuth2UserService;

	public JwtAuthenticationFilter(AuthenticationManager authenticationManager,
		CustomOAuth2UserService customOAuth2UserService) {
		this.authenticationManager = authenticationManager;
		this.customOAuth2UserService = customOAuth2UserService;
		super.setAuthenticationManager(authenticationManager);
		setFilterProcessesUrl("/api/account/login-process");
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws
		AuthenticationException {
		log.info("AttemptAuthentication = login try");


			ObjectMapper objectMapper = new ObjectMapper();
		Member member = null;
		try {
			member = objectMapper.readValue(request.getInputStream(), Member.class);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		log.info("u.username = {}", member.getEmail());

		if (member.getMemberType() == null || member.getMemberType().equals("DEFAULT")) {
			UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(member.getEmail(), member.getPw());
			return authenticationManager.authenticate(auth);
		}

		CustomOAuth2User oAuth2User = customOAuth2UserService.convertToCustomOAuth2User(
			Map.of("email", member.getEmail()));

		return new OAuth2AuthenticationToken(oAuth2User,
			oAuth2User.getAuthorities(),
			"google");

	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
		Authentication authentication) throws IOException, ServletException {

		log.info("로그인 성공");

		String jwtToken = JwtTokenManager.createJwtToken(authentication);

		log.info(jwtToken);

		response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
		response.getWriter().println(Map.of("message", "login_ok"));

	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
		AuthenticationException failed) throws IOException, ServletException {
		log.info("로그인 실패");
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.getWriter().println(Map.of("message", "login_fail"));
	}
}
