package com.oopsw.selfit.repository;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.annotation.Transactional;

import com.oopsw.selfit.domain.Comments;
import com.oopsw.selfit.dto.Comment;

@Transactional
@SpringBootTest
public class CommentRepositoryTests {

	@Autowired
	private CommentRepository commentRepository;

	@Autowired
	private CommentsRepository commentsRepository;

	// @Test
	public void testGetCommentsYes() {
		// given: 데이터 준비
		Map<String, Object> map = new HashMap<>();
		map.put("boardId", 1);  // 댓글이 존재할 수 있는 게시글
		map.put("limit", 10);
		map.put("offset", 0);

		// when: 실행
		List<Comment> comments = commentsRepository.getComments(map);

		// then: 실행결과 체크
		assertNotNull(comments);
	}

	// @Test
	public void testGetCommentsInvalidBoardId() {
		// given: 데이터 준비
		Map<String, Object> map = new HashMap<>();
		map.put("boardId", -999); // 존재하지 않는 게시글
		map.put("limit", 10);
		map.put("offset", 0);

		// when: 실행
		List<Comment> comments = commentsRepository.getComments(map);

		// then: 실행결과 체크
		assertNotNull(comments); // 실패 아님. 빈 리스트 가능
		assertEquals(0, comments.size());
	}

	// @Test
	public void testAddCommentYes() {
		// given: 데이터 준비
		Comment comment = Comment.builder()
			.commentContent("테스트 댓글입니다.")
			.commentDate(null)
			.boardId(1)
			.memberId(1)
			.build();

		// when: 실행
		int result = commentsRepository.addComment(comment);

		// then: 실행결과 체크
		assertEquals(1, result);
	}

	@Test
	public void testGetCommentsYesJpa() {
		// given: boardId = 1 에 댓글 2개 저장
		commentRepository.save(Comments.builder()
			.commentContent("댓글 1")
			.boardId(1L)
			.memberId(1)
			.build());

		commentRepository.save(Comments.builder()
			.commentContent("댓글 2")
			.boardId(1L)
			.memberId(1)
			.build());

		// when: 0번 페이지, 1개씩 페이징
		Pageable pageable = PageRequest.of(0, 5);
		Page<Comments> comments = commentRepository.findByBoardIdOrderByCommentCreatedDateDesc(1L, pageable);

		// then
		assertNotNull(comments);
	}

	@Test
	public void testGetCommentsInvalidJpa() {
		// // given: 데이터 준비
		// Map<String, Object> map = new HashMap<>();
		// map.put("boardId", -999); // 존재하지 않는 게시글
		// map.put("limit", 10);
		// map.put("offset", 0);
		//
		// // when: 실행
		// List<Comment> comments = commentRepository.getComments(map);
		//
		// // then: 실행결과 체크
		// assertNotNull(comments); // 실패 아님. 빈 리스트 가능
		// assertEquals(0, comments.size());

		// given: 존재하지 않는 boardId = -999
		Long invalidBoardId = -999L;
		Pageable pageable = PageRequest.of(0, 10);

		// when: 실행
		Page<Comments> comments = commentRepository.findByBoardIdOrderByCommentCreatedDateDesc(invalidBoardId,
			pageable);

		// then: 실행결과 체크
		assertNotNull(comments); // 빈 리스트여도 null 아님
	}

	@Test
	public void testAddCommentYesJpa() {
		// // given: 데이터 준비
		// Comment comment = Comment.builder()
		// 	.commentContent("테스트 댓글입니다.")
		// 	.commentDate(null)
		// 	.boardId(1)
		// 	.memberId(1)
		// 	.build();
		//
		// // when: 실행
		// int result = commentRepository.addComment(comment);
		//
		// // then: 실행결과 체크
		// assertEquals(1, result);
		Comments comment = Comments.builder()
			.commentContent("댓글 내용")
			.boardId(1L)
			.memberId(1)
			.build();

		Comments saved = commentRepository.save(comment);
		assertNotNull(saved.getCommentId());
	}
}
