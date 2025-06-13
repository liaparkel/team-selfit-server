package com.oopsw.selfit.auth.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.oopsw.selfit.auth.user.CustomUserDetails;
import com.oopsw.selfit.auth.user.User;
import com.oopsw.selfit.dto.LoginInfo;
import com.oopsw.selfit.repository.MemberRepository;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {
	private final MemberRepository memberRepository;

	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

		LoginInfo loginInfo = memberRepository.getLoginInfo(email);
		if (loginInfo == null) {
			throw new UsernameNotFoundException("아이디 및 비밀번호가 일치하지 않습니다.");
		}
		User user = User.builder().memberId(loginInfo.getMemberId())
			.email(email)
			.pw(loginInfo.getPw())
			.nickname(loginInfo.getNickname())
			.build();

		return new CustomUserDetails(user);
	}
}
