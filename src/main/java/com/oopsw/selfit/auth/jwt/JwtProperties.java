package com.oopsw.selfit.auth.jwt;

public interface JwtProperties {
	String SECRET = "selift";
	int TIMEOUT = 30 * 60 * 1000;
	String TOKEN_PREFIX = "Bearer ";
	String HEADER_STRING = "selfitKosta";

}
