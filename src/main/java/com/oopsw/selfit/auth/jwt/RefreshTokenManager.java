package com.oopsw.selfit.auth.jwt;

import java.util.Date;
import java.util.UUID;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class RefreshTokenManager {

	public static String createRefreshToken() {
		return JWT.create()
			.withSubject(UUID.randomUUID().toString())
			.withClaim("jti", UUID.randomUUID().toString())
			.withExpiresAt(new Date(System.currentTimeMillis() + RefreshTokenProperties.TIMEOUT))
			.sign(Algorithm.HMAC512(RefreshTokenProperties.SECRET.getBytes()));
	}

	public static void validateRefreshToken(String token) {
		JWT.require(Algorithm.HMAC512(RefreshTokenProperties.SECRET)).build().verify(token);
	}
}
