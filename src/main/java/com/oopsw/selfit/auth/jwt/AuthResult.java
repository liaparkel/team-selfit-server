package com.oopsw.selfit.auth.jwt;

import com.oopsw.selfit.dto.Member;

import lombok.Data;

@Data
public class AuthResult {
	private boolean success;
	private String message;
	private Member member;
	private String accessToken;
	private String refreshToken;
}
