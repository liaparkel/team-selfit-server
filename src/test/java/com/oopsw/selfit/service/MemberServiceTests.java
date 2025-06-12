package com.oopsw.selfit.service;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import com.oopsw.selfit.dto.Bookmark;
import com.oopsw.selfit.dto.Member;

@Transactional
@SpringBootTest
public class MemberServiceTests {

	@Autowired
	private MemberService memberService;

	@Autowired
	private BCryptPasswordEncoder encoder;

	@Test
	public void testGetMemberYes() {
		// given

		// when
		Member member = memberService.getMember(1);

		// then
		assertEquals("kim.chulsoo@example.com", member.getEmail());
	}

	@Test
	public void testGetMemberInvalid() {
		// given

		// when
		Member member = memberService.getMember(-1);

		// then
		assertNull(member);
	}

	@Test
	public void testIsEmailExistsYes() {
		// given

		// when
		boolean exists = memberService.isEmailExists("kim.chulsoo@example.com");

		// then
		assertTrue(exists);
	}

	@Test
	public void testIsEmailExistsNotExist() {
		// given

		// when
		boolean exists = memberService.isEmailExists("not.exist@example.com");

		// then
		assertFalse(exists);
	}

	@Test
	public void testIsNicknameExistsYes() {
		// given

		// when
		boolean exists = memberService.isNicknameExists("chulsoo");

		// then
		assertTrue(exists);
	}

	@Test
	public void testIsNicknameExistsNotExist() {
		// given
		String nickname = "no_such_nick";

		// when
		boolean exists = memberService.isNicknameExists(nickname);

		// then
		assertFalse(exists);
	}

	@Test
	public void testAddMemberYes() {
		// given
		String pw = "ko1234";
		Member member = Member.builder()
			.email("newu@example.com")
			.pw(pw)
			.name("새사용자")
			.nickname("newbie")
			.gender("남자")
			.birthday("2000.01.01")
			.height(175.0f)
			.weight(70.0f)
			.goal("유지")
			.memberType("DEFAULT")
			.profileImg("default.png")
			.build();

		// when
		boolean result = memberService.addMember(member);
		String encodedPw = memberService.getLoginInfo(member.getEmail()).getPw();

		// then
		assertTrue(result);
		assertTrue(encoder.matches(pw, encodedPw));
	}

	@Test
	public void testAddMemberGoogle() {
		// given
		Member member = Member.builder()
			.email("newu@example.com")
			.name("새사용자")
			.nickname("newbie")
			.gender("남자")
			.birthday("2000.01.01")
			.height(175.0f)
			.weight(70.0f)
			.goal("유지")
			.memberType("GOOGLE")
			.profileImg("default.png")
			.build();

		// when
		boolean result = memberService.addMember(member);
		String encodedPw = memberService.getLoginInfo(member.getEmail()).getPw();

		// then
		assertTrue(result);
		assertNotNull(encodedPw);
	}

	@Test
	public void testGetBookmarksYes() {
		// given
		int memberId = 1;
		int limit = 5;
		int offset = 0;

		// when
		List<Bookmark> bookmarks = memberService.getBookmarks(memberId, limit, offset);

		// then
		assertNotNull(bookmarks);
		assertTrue(bookmarks.size() <= limit);
	}

	@Test
	public void testSetMemberYes() {
		// given
		Member member = memberService.getMember(1);
		member.setNickname("updatedNick");

		// when
		boolean result = memberService.setMember(member);
		String encodedPw = memberService.getLoginInfo(member.getEmail()).getPw();

		// then
		assertTrue(result);
		assertNotNull(encodedPw);
	}

	@Test
	public void testSetMemberWithPwYes() {
		// given
		String newPw = "ko7292";
		Member member = memberService.getMember(1);
		member.setNickname("updatedNick");
		member.setPw(newPw);

		// when
		boolean result = memberService.setMember(member);
		String encodedNewPw = memberService.getLoginInfo(member.getEmail()).getPw();

		// then
		assertTrue(result);
		assertTrue(encoder.matches(newPw, encodedNewPw));
	}

	@Test
	public void testRemoveMemberYes() {
		// given

		// when
		boolean result = memberService.removeMember(1);

		// then
		assertTrue(result);
	}

	@Test
	public void testRemoveMemberInvalid() {
		// given
		int invalidId = -1;

		// when
		boolean result = memberService.removeMember(invalidId);

		// then
		assertFalse(result);
	}

}
