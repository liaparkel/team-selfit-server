package com.oopsw.selfit.service;

import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.oopsw.selfit.domain.RefreshToken;
import com.oopsw.selfit.repository.RefreshTokenRepository;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

	private final RefreshTokenRepository refreshTokenRepository;

	public void saveRefreshToken(String refreshToken) {
		this.saveRefreshToken(createRefreshToken(refreshToken));
	}

	public void saveRefreshToken(RefreshToken refreshToken) {
		refreshTokenRepository.save(refreshToken);
	}

	public RefreshToken findByJti(String jti) {
		return refreshTokenRepository.findByJti(jti);
	}

	@Transactional
	public void rotateRefreshToken(RefreshToken oldToken, RefreshToken newRefreshToken) {
		refreshTokenRepository.delete(oldToken);
		refreshTokenRepository.save(newRefreshToken);
	}

	@Transactional
	public void rotateRefreshToken(RefreshToken oldToken, String newRefreshToken) {
		refreshTokenRepository.delete(oldToken);
		refreshTokenRepository.save(this.createRefreshToken(newRefreshToken));
	}

	public RefreshToken createRefreshToken(String refreshToken) {
		return RefreshToken.builder()
			.token(refreshToken)
			.jti(JWT.decode(refreshToken).getClaim("jti").asString())
			.expiresAt(JWT.decode(refreshToken).getExpiresAt())
			.build();
	}
}
