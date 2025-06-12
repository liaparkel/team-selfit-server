package com.oopsw.selfit.auth.jwt;

//권한 인증 -> header를 기준으로 하고 싶을 때

import java.io.IOException;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.oopsw.selfit.dto.Member;
import com.oopsw.selfit.repository.MemberRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;

@Log4j2
public class JwtBasicAuthenticationFilter extends BasicAuthenticationFilter {

	private MemberRepository memberRepository;

	public JwtBasicAuthenticationFilter(AuthenticationManager authenticationManager, MemberRepository memberRepository) {
		super(authenticationManager);
		this.memberRepository = memberRepository;
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
		int memberId = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build()
			.verify(token).getClaim("memberId").asInt();

		//4. 유효한 계정 확인
		Member member = memberRepository.getMember(memberId);
		if (member == null) {
			throw new UsernameNotFoundException("잘못된 토큰입니다.");
		}

		chain.doFilter(request, response);

	}
}
