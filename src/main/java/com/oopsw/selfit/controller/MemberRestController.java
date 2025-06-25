package com.oopsw.selfit.controller;

import java.util.List;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.oopsw.selfit.auth.AuthenticatedUser;
import com.oopsw.selfit.dto.Bookmark;
import com.oopsw.selfit.dto.Member;
import com.oopsw.selfit.service.MemberService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/account")
public class MemberRestController {

	private static final int PAGE_LIMIT = 5;
	private final MemberService memberService;

	@GetMapping("/member")
	public ResponseEntity<Member> getMember(@AuthenticationPrincipal AuthenticatedUser loginUser) {
		return ResponseEntity.ok(memberService.getMember(loginUser.getMemberId()));
	}

	@PostMapping("/member")
	public ResponseEntity<Map<String, Boolean>> addMember(@RequestBody Member member) {
		memberService.addMember(member);
		return ResponseEntity.ok(Map.of("success", true));
	}

	@PutMapping("/member")
	public ResponseEntity<Map<String, Boolean>> setMember(@AuthenticationPrincipal AuthenticatedUser loginUser,
		@RequestBody Member member) {
		member.setMemberId(loginUser.getMemberId());
		return ResponseEntity.ok(Map.of("success", memberService.setMember(member)));
	}

	@DeleteMapping("/member")
	public ResponseEntity<Map<String, Boolean>> removeMember(@AuthenticationPrincipal AuthenticatedUser loginUser) {
		return ResponseEntity.ok(Map.of("success", memberService.removeMember(loginUser.getMemberId())));
	}

	@PostMapping("/check-email")
	public ResponseEntity<Map<String, Boolean>> checkEmail(@RequestBody Map<String, String> param) {
		return ResponseEntity.ok(Map.of("result", memberService.isEmailExists(param.get("email"))));
	}

	@PostMapping("/check-nickname")
	public ResponseEntity<Map<String, Boolean>> checkNickname(@RequestBody Map<String, String> param) {
		return ResponseEntity.ok(Map.of("result", memberService.isNicknameExists(param.get("nickname"))));
	}

	@PostMapping("/member/check-pw")
	public ResponseEntity<Map<String, Boolean>> checkPw(@AuthenticationPrincipal AuthenticatedUser loginUser,
		@RequestBody Map<String, String> param) {
		return ResponseEntity.ok(Map.of("success", memberService.checkPw(loginUser.getMemberId(), param.get("pw"))));
	}

	@GetMapping("/member/check-login")
	public ResponseEntity<Map<String, Boolean>> checkLoginStatus(@AuthenticationPrincipal AuthenticatedUser loginUser) {
		boolean result = (loginUser != null);
		return ResponseEntity.ok(Map.of("result", result));
	}

	@GetMapping("/member/bookmarks/{offset}")
	public ResponseEntity<List<Bookmark>> getBookmarks(@AuthenticationPrincipal AuthenticatedUser loginUser,
		@PathVariable int offset) {
		return ResponseEntity.ok(memberService.getBookmarks(loginUser.getMemberId(), PAGE_LIMIT, offset));
	}

}
