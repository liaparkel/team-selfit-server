package com.oopsw.selfit.service;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import com.oopsw.selfit.dto.Comment;
import com.oopsw.selfit.dto.Member;
import com.oopsw.selfit.repository.MemberRepository;

@Transactional
@SpringBootTest
public class CommentServiceTests {

	@Autowired
	private CommentService commentService;
	@Autowired
	private MemberRepository memberRepository;

	@Test
	public void testGetCommentsYes() {
		// given: 회원 등록
		memberRepository.addMember(Member.builder()
			.memberId(1)
			.nickname("테스터")
			.profileImg("test.png")
			.email("tester@test.com") // null 방지
			.pw("1234")
			.name("홍길동")
			.gender("M")
			.birthday("1990-01-01")
			.height(170)
			.weight(65)
			.goal("건강")
			.memberType("USER")
			.build());

		// given: 댓글 등록 (서비스 사용)
		commentService.addComment(Comment.builder()
			.commentContent("댓글 1")
			.boardId(1)
			.memberId(1)
			.build());

		commentService.addComment(Comment.builder()
			.commentContent("댓글 2")
			.boardId(1)
			.memberId(1)
			.build());

		// when
		List<Comment> comments = commentService.getComments(1, 1);

		System.out.println(comments);

		// then
		assertNotNull(comments);
	}

	@Test
	public void testGetCommentsInvalid() {
		// given
		int boardId = -999;
		int page = 1;

		// when
		List<Comment> comments = commentService.getComments(boardId, page);

		// then
		assertNotNull(comments); // null 아님
		assertEquals(0, comments.size());
	}

	@Test
	public void testAddCommentYes() {
		// given
		Comment comment = Comment.builder()
			.commentContent("JPA 댓글 저장 테스트")
			.boardId(1)
			.memberId(1)
			.build();

		// when
		boolean result = commentService.addComment(comment);

		// then
		assertTrue(result);
	}
}
