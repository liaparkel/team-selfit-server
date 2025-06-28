package com.oopsw.selfit.auth.jwt;

import java.util.Date;

import org.springframework.security.core.Authentication;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.oopsw.selfit.auth.AuthenticatedUser;

public class JwtTokenManager {

	public static String createJwtToken(Authentication authentication) {
		AuthenticatedUser authenticatedUser = (AuthenticatedUser)authentication.getPrincipal();
		return JWT.create()
			.withSubject(authenticatedUser.getEmail())
			.withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.TIMEOUT))
			.withClaim("memberId", authenticatedUser.getMemberId())
			.sign(Algorithm.HMAC512(JwtProperties.SECRET.getBytes()));
	}

	public static int validateJwtToken(String token) {
		return JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(token).getClaim("memberId").asInt();
	}
}
