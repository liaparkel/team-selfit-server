package com.oopsw.selfit.auth.jwt;

public interface JwtProperties {
	String SECRET = "c0783cea-e162-4965-927d-c19cd0a38791";
	int TIMEOUT = 10 * 60 * 1000;
	String TOKEN_PREFIX = "Bearer ";
	String HEADER_STRING = "selfitKosta";

}
