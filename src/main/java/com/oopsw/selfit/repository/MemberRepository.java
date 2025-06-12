package com.oopsw.selfit.repository;

import org.apache.ibatis.annotations.Mapper;

import com.oopsw.selfit.dto.LoginInfo;
import com.oopsw.selfit.dto.Member;

@Mapper
public interface MemberRepository {
	Member getMember(int memberId);

	LoginInfo getLoginInfo(String email);

	String getPw(int memberId);

	String checkExistEmail(String email);

	String checkExistNickname(String nickname);

	int setPw(int memberId, String newPw);

	int addMember(Member member);

	int setMember(Member newMember);

	int removeMember(int memberId);
}