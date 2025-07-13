package com.oopsw.selfit.auth.jwt;

//권한 인증 -> header를 기준으로 하고 싶을 때

import java.io.IOException;
import java.util.Map;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.oopsw.selfit.auth.service.CustomOAuth2UserService;
import com.oopsw.selfit.auth.service.CustomUserDetailsService;
import com.oopsw.selfit.auth.user.CustomOAuth2User;
import com.oopsw.selfit.dto.Member;
import com.oopsw.selfit.repository.MemberRepository;
import com.oopsw.selfit.service.RefreshTokenService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JwtBasicAuthenticationFilter extends BasicAuthenticationFilter {

	private final MemberRepository memberRepository;
	private final CustomOAuth2UserService customOAuth2UserService;
	private final CustomUserDetailsService customUserDetailsService;
	private final RefreshTokenService refreshTokenService;

	public JwtBasicAuthenticationFilter(AuthenticationManager authenticationManager, MemberRepository memberRepository,
		CustomOAuth2UserService customOAuth2UserService, CustomUserDetailsService customUserDetailsService,
		RefreshTokenService refreshTokenService) {
		super(authenticationManager);
		this.memberRepository = memberRepository;
		this.customOAuth2UserService = customOAuth2UserService;
		this.customUserDetailsService = customUserDetailsService;
		this.refreshTokenService = refreshTokenService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws
		IOException,
		ServletException {
		log.info("JwtBasicAuthentication: [{}] {} {}", request.getMethod(), request.getRequestURI(),
			getClientIP(request));

		String jwtToken = request.getHeader(JwtProperties.HEADER_STRING).replace(JwtProperties.TOKEN_PREFIX, "");
		String refreshToken = null;
		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals(RefreshTokenProperties.COOKIE)) {
					refreshToken = cookie.getValue();
					break;
				}
			}
		}

		//1.Jwt토큰이 있는지 확인
		if (jwtToken == null || jwtToken.trim().isEmpty()) {
			sendErrorResponse(response, "AccessToken is invalid");
			return;
		}

		// 2.Jwt토큰 검증
		AuthResult result = checkJwtToken(jwtToken, refreshToken, response);
		if (result.getMember() == null || result.getMessage().equals("SignatureVerificationException")) {
			sendErrorResponse(response, "AccessToken is invalid");
			return;
		}

		// 3.기존 Jwt토큰 만료시, refreshToken으로 재발급
		if (result.getMessage().equals("TokenExpiredException")) {
			if (!refreshJwtAccessToken(result)) {
				sendErrorResponse(response, "AccessToken is invalid");
				return;
			}
			response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + result.getAccessToken());
			addRefreshTokenCookie(response, result.getRefreshToken());
		}

		Member member = result.getMember();
		Authentication authentication = null;
		if (member.getMemberType().equals("DEFAULT")) {
			UserDetails userDetails = customUserDetailsService.loadUserByUsername(member.getEmail());
			authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

		} else {
			Map<String, Object> attributes = Map.of("email", member.getEmail());
			CustomOAuth2User oAuth2User = customOAuth2UserService.convertToCustomOAuth2User(attributes);
			authentication = new UsernamePasswordAuthenticationToken(oAuth2User, null, oAuth2User.getAuthorities());
		}

		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(request, response);

	}

	private boolean refreshJwtAccessToken(AuthResult result) throws IOException {
		try {
			refreshTokenService.rotateTokensAndCreateNew(result);
		} catch (RuntimeException e) {
			e.printStackTrace();
			return false;
		}

		return true;
	}

	private void addRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
		response.setHeader("Set-Cookie",
			String.format("%s=%s; Max-Age=%d; Path=%s; HttpOnly; SameSite=%s", RefreshTokenProperties.COOKIE,
				refreshToken, RefreshTokenProperties.TIMEOUT, "/", "Strict"));
	}

	private AuthResult checkJwtToken(String jwtToken, String refreshToken, HttpServletResponse response) throws
		IOException {
		AuthResult result = new AuthResult();
		result.setRefreshToken(refreshToken);

		try {
			int memberId = JwtTokenManager.validateJwtToken(jwtToken);
			Member member = memberRepository.getMember(memberId);
			result.setSuccess(true);
			result.setMember(member);
			result.setAccessToken(jwtToken);
			result.setMessage("Authenticated");

		} catch (TokenExpiredException e) {
			int memberId = JWT.decode(jwtToken).getClaim("memberId").asInt();
			Member member = memberRepository.getMember(memberId);
			result.setSuccess(false);
			result.setMember(member);
			result.setMessage(e.getClass().getSimpleName());
		} catch (SignatureVerificationException e) {
			result.setSuccess(false);
			result.setMessage(e.getClass().getSimpleName());
		}

		return result;
	}

	private void sendErrorResponse(HttpServletResponse response, String message) throws IOException {
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setContentType("application/json");
		response.setCharacterEncoding("UTF-8");
		response.getWriter().println(Map.of("error", "UNAUTHORIZED", "message", message));
	}

	private String getClientIP(HttpServletRequest request) {
		String xForwardedFor = request.getHeader("X-Forwarded-For");
		return xForwardedFor != null ? xForwardedFor.split(",")[0] : request.getRemoteAddr();
	}

}
