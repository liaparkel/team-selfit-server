package com.oopsw.selfit.auth.jwt;

import java.io.IOException;
import java.util.Date;
import java.util.Map;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.oopsw.gjwt.auth.PrincipalDetails;
import com.oopsw.gjwt.domain.User;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

@Log4j2
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager authenticationManager;

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws
		AuthenticationException {
		log.info("attemptAuthentication = 로그인 시도");
		//로그인 정보 추출

		try {
			ObjectMapper objectMapper = new ObjectMapper();
			log.info(request.getInputStream());
			User u = objectMapper.readValue(request.getInputStream(), User.class);
			log.info("u.username = " + u.getUsername());
			log.info("u.password = " + u.getPassword());

			UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(u.getUsername(), u.getPassword());

			Authentication authenticate = authenticationManager.authenticate(auth);
			PrincipalDetails details = (PrincipalDetails)authenticate.getPrincipal();

			log.info(details.getUser().getEmail());
			return authenticate;
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
		Authentication authResult) throws IOException, ServletException {

		log.info("로그인 성공");

		//3. JWT 작성
		PrincipalDetails details = (PrincipalDetails)authResult.getPrincipal();
		String jwtToken = JWT.create()
			.withSubject(details.getUser().getEmail())
			.withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.TIMEOUT))
			.withClaim("id", details.getUser().getId())
			.withClaim("username", details.getUser().getUsername())
			.withClaim("email", details.getUser().getEmail())
			.sign(Algorithm.HMAC256(JwtProperties.SECRET));

		log.info(jwtToken);

		//4. 웹브라우저에 전달
		response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
		response.getWriter().println(Map.of("message", "login_ok"));

	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
		AuthenticationException failed) throws IOException, ServletException {
		log.info("로그인 실패");
	}
}
