package com.oopsw.selfit.auth.jwt;

public interface RefreshTokenProperties {
	String SECRET = "4327f08f-19a6-4790-a23b-b5524be89d14";
	int TIMEOUT = 12 * 60 * 60 * 1000;
	String COOKIE = "s_rt";
}
