package com.oopsw.selfit.service;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.List;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.oopsw.selfit.dto.Bookmark;
import com.oopsw.selfit.dto.LoginInfo;
import com.oopsw.selfit.dto.Member;
import com.oopsw.selfit.repository.BoardRepository;
import com.oopsw.selfit.repository.MemberRepository;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class MemberService {

	private final List<String> genders = List.of("남자", "여자");
	private final List<String> goals = List.of("유지", "감량", "증량");
	private final List<String> memberTypes = List.of("DEFAULT", "GOOGLE");

	private final MemberRepository memberRepository;
	private final BoardRepository boardRepository;
	private final BCryptPasswordEncoder encoder;

	public Member getMember(int memberId) {
		return memberRepository.getMember(memberId);
	}

	public LoginInfo getLoginInfo(String email) {
		return memberRepository.getLoginInfo(email);
	}

	public boolean checkPw(int memberId, String pw) {
		return encoder.matches(pw.strip(), memberRepository.getPw(memberId));
	}

	public boolean isEmailExists(String email) {
		return memberRepository.checkExistEmail(email) != null;
	}

	public boolean isNicknameExists(String nickname) {
		return memberRepository.checkExistNickname(nickname) != null;
	}

	public boolean addMember(Member member) {

		if (!member.getMemberType().equals("DEFAULT")) {
			member.setPw(generateRandomString());
		}
		member.setPw(encoder.encode(member.getPw()));

		String errorMessage = validateMember(member);
		if (errorMessage != null) {
			throw new DataIntegrityViolationException(errorMessage);
		}

		return memberRepository.addMember(member) > 0;
	}

	public List<Bookmark> getBookmarks(int memberId, int limit, int offset) {
		return boardRepository.getBookmarks(memberId, limit, offset);
	}

	public boolean setMember(Member newMember) {

		if (newMember.getPw() != null) {
			newMember.setPw(encoder.encode(newMember.getPw()));
			memberRepository.setPw(newMember.getMemberId(), newMember.getPw());
		}

		return memberRepository.setMember(newMember) > 0;
	}

	public boolean removeMember(int memberId) {
		return memberRepository.removeMember(memberId) > 0;
	}

	private String generateRandomString() {
		long currentTime = System.currentTimeMillis(); // 현재 시간(ms)
		int randomNumber = (int)(Math.random() * 100000); // 0 ~ 99999

		return currentTime + "_" + randomNumber;
	}

	private String validateMember(Member member) {

		if (memberRepository.checkExistEmail(member.getEmail()) != null) {
			return "Email is duplicated";
		}

		if (member.getPw() == null) {
			return "Password is null";
		}

		if (member.getName() == null) {
			return "Name is null";
		}

		if (memberRepository.checkExistNickname(member.getNickname()) != null) {
			return "Nickname is duplicated";
		}

		if (member.getGender() != null && !genders.contains(member.getGender())) {
			return "gender is invalid";
		}

		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
		if (member.getBirthday() != null) {
			try {
				LocalDate.parse(member.getBirthday(), formatter);
			} catch (DateTimeParseException e) {
				return "Birthday is invalid format";
			}
		}

		if (member.getHeight() < 0 || member.getHeight() > 250) {
			return "Height is invalid";
		}

		if (member.getWeight() < 0 || member.getWeight() > 300) {
			return "Weight is invalid";
		}

		if (member.getGoal() != null && !goals.contains(member.getGoal())) {
			return "Goal is invalid";
		}

		if (member.getJoinDate() != null) {
			return "joinDate must be null";
		}

		if (member.getMemberType() == null || !memberTypes.contains(member.getMemberType())) {
			return "memberType is invalid";
		}

		return null;
	}

}
