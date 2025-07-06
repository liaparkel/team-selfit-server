package com.oopsw.selfit.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.oopsw.selfit.auth.jwt.AuthResult;
import com.oopsw.selfit.auth.jwt.JwtTokenManager;
import com.oopsw.selfit.auth.jwt.RefreshTokenManager;
import com.oopsw.selfit.domain.RefreshToken;
import com.oopsw.selfit.repository.RefreshTokenRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

	private final RefreshTokenRepository refreshTokenRepository;

	@Transactional
	public void rotateTokensAndCreateNew(AuthResult result) {

		//1. refreshToken이 있는지 확인
		String refreshToken = result.getRefreshToken();
		if (refreshToken == null || refreshToken.trim().isEmpty()) {
			throw new RuntimeException("refreshToken is invalid");
		}

		//2. refreshToken이 유효한 jwt인지, 유효기간이 넘었는지 확인
		RefreshTokenManager.validateRefreshToken(result.getRefreshToken());

		//3. refreshToken이 db에서 있는지 조회(jti로 조회)
		DecodedJWT decode = JWT.decode(refreshToken);
		String jti = decode.getClaim("jti").asString();
		RefreshToken oldRefreshToken = this.findByJti(jti);
		if (oldRefreshToken.getUsed() == 1) {
			throw new RuntimeException("refreshToken not found");
		}
		System.out.println(result.getMember().getMemberId());
		System.out.println(oldRefreshToken.getMemberId());
		if (oldRefreshToken.getMemberId() != result.getMember().getMemberId()) {
			throw new RuntimeException("invalid refreshToken");
		}

		//4. 새로운 AccessToken 발급 및 refreshToken도 새로 발급
		String newJwtToken = JwtTokenManager.createJwtToken(result.getMember().getMemberId());
		String newRefreshToken = RefreshTokenManager.createRefreshToken();

		//5. 기존에 있는 oldRefreshToken 무효화
		this.rotateRefreshToken(oldRefreshToken, newRefreshToken, oldRefreshToken.getMemberId());
		result.setAccessToken(newJwtToken);
		result.setRefreshToken(newRefreshToken);
	}

	public void saveRefreshToken(String refreshToken, int memberId) {
		this.saveRefreshToken(createRefreshToken(refreshToken, memberId));
	}

	public void saveRefreshToken(RefreshToken refreshToken) {
		refreshTokenRepository.save(refreshToken);
	}

	public RefreshToken findByJti(String jti) {
		return refreshTokenRepository.findByJti(jti);
	}

	public void rotateRefreshToken(RefreshToken oldToken, String newRefreshToken, int memberId) {
		oldToken.setUsed(1);
		refreshTokenRepository.save(this.createRefreshToken(newRefreshToken, memberId));
	}

	public RefreshToken createRefreshToken(String refreshToken, int memberId) {
		return RefreshToken.builder()
			.jti(JWT.decode(refreshToken).getClaim("jti").asString())
			.memberId(memberId)
			.used(0)
			.expiresAt(JWT.decode(refreshToken).getExpiresAt())
			.build();
	}

}
