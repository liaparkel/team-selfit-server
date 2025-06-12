package com.oopsw.selfit.controller;

import java.util.List;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.oopsw.selfit.auth.AuthenticatedUser;
import com.oopsw.selfit.auth.service.CustomOAuth2UserService;
import com.oopsw.selfit.auth.service.CustomUserDetailsService;
import com.oopsw.selfit.auth.user.CustomOAuth2User;
import com.oopsw.selfit.dto.Bookmark;
import com.oopsw.selfit.dto.Member;
import com.oopsw.selfit.service.MemberService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/account")
public class MemberRestController {

	private static final int PAGE_LIMIT = 5;
	private static Gson gson = new Gson();
	private final MemberService memberService;
	private final CustomOAuth2UserService customOAuth2UserService;
	private final CustomUserDetailsService customUserDetailsService;

	@GetMapping("/member")
	public ResponseEntity<Member> getMember(@AuthenticationPrincipal AuthenticatedUser loginUser) {
		return ResponseEntity.ok(memberService.getMember(loginUser.getMemberId()));
	}

	@PostMapping("/member")
	public ResponseEntity<Map<String, Boolean>> addMember(@RequestBody Member member, HttpServletRequest request) {
		memberService.addMember(member);
		saveSession(member, request);

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
	public ResponseEntity<Map<String, Boolean>> checkEmail(@RequestBody String jsonData) {
		String email = gson.fromJson(jsonData, JsonObject.class)
			.get("email")
			.getAsString();

		return ResponseEntity.ok(Map.of("result", memberService.isEmailExists(email)));
	}

	@PostMapping("/check-nickname")
	public ResponseEntity<Map<String, Boolean>> checkNickname(@RequestBody String jsonData) {
		String nickname = gson.fromJson(jsonData, JsonObject.class)
			.get("nickname")
			.getAsString();

		return ResponseEntity.ok(Map.of("result", memberService.isNicknameExists(nickname)));
	}

	@PostMapping("/member/check-pw")
	public ResponseEntity<Map<String, Boolean>> checkPw(@AuthenticationPrincipal AuthenticatedUser loginUser,
		@RequestBody String jsonData) {
		String pw = gson.fromJson(jsonData, JsonObject.class)
			.get("pw")
			.getAsString();
		return ResponseEntity.ok(Map.of("success", memberService.checkPw(loginUser.getMemberId(), pw)));
	}

	@GetMapping("/member/check-login")
	public ResponseEntity<Map<String, Boolean>> checkLoginStatus(@AuthenticationPrincipal AuthenticatedUser loginUser) {
		boolean result = false;
		if (loginUser != null) {
			result = true;
		}
		return ResponseEntity.ok(Map.of("result", result));
	}

	@GetMapping("/member/bookmarks/{offset}")
	public ResponseEntity<List<Bookmark>> getBookmarks(@AuthenticationPrincipal AuthenticatedUser loginUser,
		@PathVariable int offset) {
		return ResponseEntity.ok(memberService.getBookmarks(loginUser.getMemberId(), PAGE_LIMIT, offset));
	}

	private void saveSession(Member member, HttpServletRequest request) {
		Authentication authentication;

		if (member.getMemberType().equals("DEFAULT")) {
			UserDetails userDetails = customUserDetailsService.loadUserByUsername(member.getEmail());
			authentication = new UsernamePasswordAuthenticationToken(
				userDetails, null, userDetails.getAuthorities()
			);

		} else {
			Map<String, Object> attributes = Map.of("email", member.getEmail());
			CustomOAuth2User oAuth2User = customOAuth2UserService.convertToCustomOAuth2User(attributes);

			authentication = new UsernamePasswordAuthenticationToken(
				oAuth2User, null, oAuth2User.getAuthorities()
			);

		}

		HttpSession session = request.getSession(true);
		session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
			SecurityContextHolder.getContext());
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}
}
