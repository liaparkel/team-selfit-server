package com.oopsw.selfit.auth.jwt;

//권한 인증 -> header를 기준으로 하고 싶을 때

import java.io.IOException;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.oopsw.gjwt.auth.PrincipalDetails;
import com.oopsw.gjwt.domain.User;
import com.oopsw.gjwt.repository.UserRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;

@Log4j2
public class JwtBasicAuthenticationFilter extends BasicAuthenticationFilter {

	private final UserRepository userRepository;

	public JwtBasicAuthenticationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
		log.info("JwtBasicAuthenticationFilter");
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws
		IOException,
		ServletException {
		log.info("doFilterInternal: " + request.getRequestURI());


		String jwtToken = request.getHeader(JwtProperties.HEADER_STRING);
		log.info("doFilterInternal: " + jwtToken);

		//1. jwt 토큰이 있는지 확인

		if (jwtToken == null || jwtToken.trim().isEmpty() || !jwtToken.startsWith(JwtProperties.TOKEN_PREFIX)) {
			chain.doFilter(request, response);
			return;
		}

		//2. jwt 토큰
		String token = jwtToken.replace(JwtProperties.TOKEN_PREFIX, "");


		//3. jwt 서명 확인
		String username = JWT.require(Algorithm.HMAC256(JwtProperties.SECRET)).build()
			.verify(token).getClaim("username").asString();

		//4. 유효한 계정 확인
		if (username != null) {
			User user = userRepository.findByUsername(username);
			PrincipalDetails details = new PrincipalDetails(user);
			Authentication auth = new UsernamePasswordAuthenticationToken(details, null, details.getAuthorities());

			//세션 접근
			SecurityContextHolder.getContext().setAuthentication(auth);
		}

		chain.doFilter(request, response);

	}
}
