package com.oopsw.selfit.repository;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import com.oopsw.selfit.dto.LoginInfo;
import com.oopsw.selfit.dto.Member;

@SpringBootTest
@Transactional
public class MemberRepositoryTests {

	@Autowired
	private MemberRepository memberRepository;

	@Test
	public void testGetMemberYes() {
		//given

		//when
		Member member = memberRepository.getMember(1);

		//then
		assertEquals("kim.chulsoo@example.com", member.getEmail());
	}

	@Test
	public void testGetMemberInvalid() {
		//given

		//when
		Member member = memberRepository.getMember(-1);

		//then
		assertNull(member);
	}

	@Test
	public void testGetLoginInfoYes() {
		//given

		//when
		LoginInfo info = memberRepository.getLoginInfo("park.minsu@example.com");

		//then
		assertEquals(3, info.getMemberId());
	}

	@Test
	public void testGetLoginInfoInvalid() {
		//given

		//when
		LoginInfo info = memberRepository.getLoginInfo("invalid@example.com");

		//then
		assertNull(info);
	}

	// 이메일 중복 있음 (Yes)
	@Test
	public void testCheckExistEmailYes() {
		//given
		String existingEmail = "kim.chulsoo@example.com";

		//when
		String email = memberRepository.checkExistEmail(existingEmail);

		//then
		assertEquals(existingEmail, email);
	}

	// 이메일 중복 없음 (No)
	@Test
	public void testCheckExistEmailNotExist() {
		//given
		String nonExistingEmail = "not.exist@example.com";

		//when
		String email = memberRepository.checkExistEmail(nonExistingEmail);

		//then
		assertNull(email);
	}

	// 닉네임 중복 있음 (Yes)
	@Test
	public void testCheckExistNicknameYes() {
		//given
		String existingNickname = "chulsoo";

		//when
		String nickname = memberRepository.checkExistNickname(existingNickname);

		//then
		assertEquals(existingNickname, nickname);
	}

	// 닉네임 중복 없음 (No)
	@Test
	public void testCheckExistNicknameNotExist() {
		//given
		String nonExistingNickname = "no_such_nick";

		//when
		String nickname = memberRepository.checkExistNickname(nonExistingNickname);

		//then
		assertNull(nickname);
	}

	@Test
	public void testSetPasswordYes() {
		//given

		//when
		int result = memberRepository.setPw(1, "newPassword");

		//then
		assertEquals(1, result);
	}

	@Test
	public void testAddMemberYes() {
		//given
		Member member = Member.builder()
			.email("new@example.com")
			.pw("securepass")
			.name("김아무")
			.nickname("testnick")
			.gender("남성")
			.birthday("1999-01-01")
			.height(180.0f)
			.weight(75.0f)
			.goal("건강 유지")
			.memberType("일반회원")
			.profileImg("img.jpg")
			.build();

		//when
		int result = memberRepository.addMember(member);

		//then
		assertEquals(1, result);
	}

	@Test
	public void testSetMemberYes() {
		//given
		Member member = memberRepository.getMember(1);
		member.setNickname("newNickname");

		//when
		int result = memberRepository.setMember(member);

		//then
		assertEquals(1, result);
	}

	@Test
	public void testSetMemberNoChange() {
		//given
		Member member = memberRepository.getMember(1);

		//when
		int result = memberRepository.setMember(member);

		//then
		assertEquals(1, result);
	}
	
	@Test
	public void testRemoveMemberYes() {
		//given

		//when
		int deleted = memberRepository.removeMember(1);

		//then
		assertEquals(1, deleted);
	}

	@Test
	public void testRemoveMemberInvalid() {
		//given

		//when
		int deleted = memberRepository.removeMember(-1);

		//then
		assertEquals(0, deleted);
	}

}