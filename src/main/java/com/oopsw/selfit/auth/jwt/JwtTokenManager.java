package com.oopsw.selfit.auth.jwt;

import java.util.Date;
import java.util.UUID;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class JwtTokenManager {

	public static String createJwtToken(int memberId) {
		return JWT.create()
			.withSubject(UUID.randomUUID().toString())
			.withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.TIMEOUT))
			.withClaim("memberId", memberId)
			.sign(Algorithm.HMAC512(JwtProperties.SECRET.getBytes()));
	}

	public static int validateJwtToken(String token) {
		return JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(token).getClaim("memberId").asInt();
	}
}
