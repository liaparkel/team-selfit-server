package com.oopsw.selfit.auth.jwt;

import java.util.Map;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import com.oopsw.selfit.auth.service.CustomOAuth2UserService;
import com.oopsw.selfit.auth.service.CustomUserDetailsService;
import com.oopsw.selfit.auth.user.CustomOAuth2User;
import com.oopsw.selfit.dto.Member;
import com.oopsw.selfit.repository.MemberRepository;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class CustomJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

	private final MemberRepository memberRepository;
	private final CustomUserDetailsService userDetailsService;
	private final CustomOAuth2UserService oAuth2UserService;

	@Override
	public AbstractAuthenticationToken convert(Jwt jwt) {
		int memberId = jwt.getClaim("memberId");
		Member member = memberRepository.getMember(memberId);
		if (member == null) {
			throw new UsernameNotFoundException("Invalid user");
		}

		if ("DEFAULT".equals(member.getMemberType())) {
			UserDetails userDetails = userDetailsService.loadUserByUsername(member.getEmail());
			return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
		}

		Map<String, Object> attributes = Map.of("email", member.getEmail());
		CustomOAuth2User oAuth2User = oAuth2UserService.convertToCustomOAuth2User(attributes);
		return new UsernamePasswordAuthenticationToken(oAuth2User, null, oAuth2User.getAuthorities());
	}
}
