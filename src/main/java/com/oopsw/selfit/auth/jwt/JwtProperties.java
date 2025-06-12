package com.oopsw.selfit.auth.jwt;

public interface JwtProperties {
	String SECRET = "oopsw";
	int TIMEOUT = 10 * 60 * 1000;
	String TOKEN_PREFIX = "Bearer ";
	String HEADER_STRING = "Authorization";

}
