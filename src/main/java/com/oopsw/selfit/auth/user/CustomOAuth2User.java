package com.oopsw.selfit.auth.user;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.oopsw.selfit.auth.AuthenticatedUser;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class CustomOAuth2User implements OAuth2User, AuthenticatedUser {
	private final User user;
	private final Map<String, Object> attributes;

	@Override
	public int getMemberId() {
		return user.getMemberId();
	}

	@Override
	public String getEmail() {
		return user.getEmail();
	}

	@Override
	public String getNickname() {
		return user.getNickname();
	}

	@Override
	public String getName() {
		return null;
	}

	@Override
	public Map<String, Object> getAttributes() {
		return attributes;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return List.of(new SimpleGrantedAuthority(user.getRole()));
	}

}
