package com.oopsw.selfit.auth.service;

import java.util.Map;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import com.oopsw.selfit.auth.user.CustomOAuth2User;
import com.oopsw.selfit.auth.user.User;
import com.oopsw.selfit.service.MemberService;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
	private final MemberService memberService;
	private final BCryptPasswordEncoder encoder;

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		OAuth2User oAuth2User = super.loadUser(userRequest);
		Map<String, Object> attributes = oAuth2User.getAttributes();
		return convertToCustomOAuth2User(attributes);
	}

	public CustomOAuth2User convertToCustomOAuth2User(Map<String, Object> attributes) {
		String email = (String)attributes.get("email");

		if (!memberService.isEmailExists(email)) {
			RequestContextHolder.currentRequestAttributes()
				.setAttribute("email", attributes.get("email"), RequestAttributes.SCOPE_SESSION);

			RequestContextHolder.currentRequestAttributes()
				.setAttribute("name", attributes.get("name"), RequestAttributes.SCOPE_SESSION);
			throw new OAuth2AuthenticationException("NEED_SIGNUP");
		}

		int memberId = memberService.getLoginInfo(email).getMemberId();
		User user = User.builder()
			.memberId(memberId)
			.email(email)
			.build();
		return new CustomOAuth2User(user, attributes);
	}

}