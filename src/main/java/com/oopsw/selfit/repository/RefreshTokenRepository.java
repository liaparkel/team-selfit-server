package com.oopsw.selfit.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.oopsw.selfit.domain.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Integer> {

	RefreshToken findByJti(String jti);
}
