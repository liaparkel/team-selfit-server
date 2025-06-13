package com.oopsw.selfit.auth.jwt;

import java.io.IOException;
import java.util.Map;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.oopsw.selfit.auth.AuthenticatedUser;
import com.oopsw.selfit.auth.user.User;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;

@Log4j2
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager authenticationManager;

	public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
		super.setAuthenticationManager(authenticationManager);
		setFilterProcessesUrl("/api/account/login-process");
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws
		AuthenticationException {
		log.info("AttemptAuthentication = login try");

		try {
			ObjectMapper objectMapper = new ObjectMapper();
			User user = objectMapper.readValue(request.getInputStream(), User.class);
			log.info("u.username = {}", user.getEmail());
			log.info("u.password = {}", user.getPw());

			UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(user.getEmail(),user.getPw());

			Authentication authenticate = authenticationManager.authenticate(auth);
			AuthenticatedUser principal = (AuthenticatedUser)authenticate.getPrincipal();

			log.info(principal.getMemberId());
			return authenticate;
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
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
		response.getWriter().println(Map.of("message", "login_fail"));
	}
}
