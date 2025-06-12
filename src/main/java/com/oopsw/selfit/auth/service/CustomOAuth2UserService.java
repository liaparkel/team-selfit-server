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
import com.oopsw.selfit.dto.LoginInfo;
import com.oopsw.selfit.dto.Member;
import com.oopsw.selfit.service.MemberService;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
	private final MemberService memberService;

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		OAuth2User oAuth2User = super.loadUser(userRequest);
		Map<String, Object> attributes = oAuth2User.getAttributes();
		return convertToCustomOAuth2User(attributes);
	}

	public CustomOAuth2User convertToCustomOAuth2User(Map<String, Object> attributes) {
		String email = (String)attributes.get("email");

		//회원가입 이력이 없는 경우 회원가입페이지로 유도
		if (!memberService.isEmailExists(email)) {
			RequestContextHolder.currentRequestAttributes()
				.setAttribute("email", attributes.get("email"), RequestAttributes.SCOPE_REQUEST);

			RequestContextHolder.currentRequestAttributes()
				.setAttribute("name", attributes.get("name"), RequestAttributes.SCOPE_REQUEST);
			throw new OAuth2AuthenticationException("회원가입 이력이 없습니다.");
		}

		LoginInfo loginInfo = memberService.getLoginInfo(email);
		User user = User.builder()
			.memberId(loginInfo.getMemberId())
			.email(email)
			.nickname(loginInfo.getNickname())
			.build();
		return new CustomOAuth2User(user, attributes);
	}

}