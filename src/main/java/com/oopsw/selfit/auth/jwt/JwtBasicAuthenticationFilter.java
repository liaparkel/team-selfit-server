package com.oopsw.selfit.auth.jwt;

//권한 인증 -> header를 기준으로 하고 싶을 때

import java.io.IOException;
import java.util.Map;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.oopsw.selfit.auth.service.CustomOAuth2UserService;
import com.oopsw.selfit.auth.service.CustomUserDetailsService;
import com.oopsw.selfit.auth.user.CustomOAuth2User;
import com.oopsw.selfit.dto.Member;
import com.oopsw.selfit.repository.MemberRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JwtBasicAuthenticationFilter extends BasicAuthenticationFilter {

	private final MemberRepository memberRepository;
	private final CustomOAuth2UserService customOAuth2UserService;
	private final CustomUserDetailsService customUserDetailsService;

	public JwtBasicAuthenticationFilter(AuthenticationManager authenticationManager, MemberRepository memberRepository,
		CustomOAuth2UserService customOAuth2UserService, CustomUserDetailsService customUserDetailsService) {
		super(authenticationManager);
		this.memberRepository = memberRepository;
		this.customOAuth2UserService = customOAuth2UserService;
		this.customUserDetailsService = customUserDetailsService;
		log.info("JwtBasicAuthenticationFilter");
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws
		IOException,
		ServletException {
		log.info("doFilterInternal: " + request.getRequestURI());

		try {
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
			int memberId = JwtTokenManager.checkJwtToken(token);

			//4. 유효한 계정 확인(DB조회)
			Member member = memberRepository.getMember(memberId);
			if (member == null) {
				throw new UsernameNotFoundException("잘못된 계정입니다.");
			}

			Authentication authentication;
			if (member.getMemberType().equals("DEFAULT")) {
				UserDetails userDetails = customUserDetailsService.loadUserByUsername(member.getEmail());
				authentication = new UsernamePasswordAuthenticationToken(userDetails, null,
					userDetails.getAuthorities());

			} else {
				Map<String, Object> attributes = Map.of("email", member.getEmail());
				CustomOAuth2User oAuth2User = customOAuth2UserService.convertToCustomOAuth2User(attributes);
				authentication = new UsernamePasswordAuthenticationToken(oAuth2User, null, oAuth2User.getAuthorities());
			}

			SecurityContextHolder.getContext().setAuthentication(authentication);
			chain.doFilter(request, response);
		} catch (TokenExpiredException e) {
			log.error("JWT 인증 실패: {}", e.getMessage());
			sendErrorResponse(response, "액세스 토큰 만료");
		} catch (UsernameNotFoundException e) {
			log.error("JWT 인증 실패: {}", e.getMessage());
			sendErrorResponse(response, e.getMessage());
		}
	}

	private void sendErrorResponse(HttpServletResponse response, String message) throws IOException {
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setContentType("application/json");
		response.setCharacterEncoding("UTF-8");
		response.getWriter().println(Map.of("error", "UNAUTHORIZED", "message", message));
	}
}
