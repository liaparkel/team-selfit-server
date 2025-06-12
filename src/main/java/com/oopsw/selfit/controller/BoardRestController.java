package com.oopsw.selfit.controller;

import java.util.HashMap;
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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.oopsw.selfit.auth.AuthenticatedUser;
import com.oopsw.selfit.dto.Board;
import com.oopsw.selfit.dto.Comment;
import com.oopsw.selfit.service.BoardService;
import com.oopsw.selfit.service.CommentService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping("/api/board")
public class BoardRestController {

	private final BoardService boardService;
	private final CommentService commentService;

	@GetMapping("/list")
	public ResponseEntity<List<Board>> getBoards(@RequestParam int page,
		@RequestParam int categoryId,
		@RequestParam(defaultValue = "") String keyword,
		@RequestParam(defaultValue = "recent") String sortOrder) {

		log.info("getBoards - page: {}, categoryId: {}, keyword: {}, sortOrder: {}", page, categoryId, keyword,
			sortOrder);
		List<Board> boards = boardService.getBoards(categoryId, keyword, sortOrder, page);
		return ResponseEntity.ok(boards);

	}

	@GetMapping("/{boardId}")
	public ResponseEntity<Map<String, Object>> getBoard(@AuthenticationPrincipal AuthenticatedUser loginUser,
		@PathVariable int boardId) {
		log.info("getBoard - boardId: {}", boardId);

		int currentUserId = 0;
		if (loginUser != null) {
			currentUserId = loginUser.getMemberId();
		}

		log.info("getBoard - loginUser: {}", currentUserId);
		Board board = Board.builder()
			.boardId(boardId)
			.build();
		Board result = boardService.getBoard(board);
		log.info("getBoard - result: {}", result);

		Map<String, Object> resp = new HashMap<>();
		resp.put("board", result);
		resp.put("currentUserId", currentUserId);

		return ResponseEntity.ok(resp);
	}

	@GetMapping("/comments")
	public ResponseEntity<List<Comment>> getComments(
		@RequestParam("boardId") int boardId,
		@RequestParam(name = "page", defaultValue = "1") int page) {
		List<Comment> comments = commentService.getComments(boardId, page);
		return ResponseEntity.ok(comments);
	}

	@PostMapping("/add")
	public ResponseEntity<String> addBoard(@AuthenticationPrincipal AuthenticatedUser loginUser,
		@RequestBody Board board) {
		board.setMemberId(loginUser.getMemberId());
		log.info("addBoard - board: {}", board);
		boardService.addBoard(board);
		return ResponseEntity.ok("게시글 등록 성공");
	}

	@PostMapping("/comment/add")
	public ResponseEntity<String> addComment(@AuthenticationPrincipal AuthenticatedUser loginUser,
		@RequestBody Comment comment) {
		comment.setMemberId(loginUser.getMemberId());
		log.info("addComment - comment: {}", comment);
		commentService.addComment(comment);
		return ResponseEntity.ok("댓글 등록 성공");
	}

	@DeleteMapping("/delete/{boardId}")
	public ResponseEntity<String> deleteBoard(
		@AuthenticationPrincipal AuthenticatedUser loginUser,
		@PathVariable int boardId) {

		// 요청 DTO에 boardId와 memberId(작성자 ID)를 세팅
		Board toDelete = Board.builder()
			.boardId(boardId)
			.memberId(loginUser.getMemberId())
			.build();

		// 서비스 호출만, 실패 시 예외가 던져짐
		boardService.removeBoard(toDelete);

		// 예외가 없었다면 삭제 성공
		return ResponseEntity.ok("게시글 삭제 성공");
	}

	@PutMapping("/edit/{boardId}")
	public ResponseEntity<String> setBoard(
		@AuthenticationPrincipal AuthenticatedUser loginUser,
		@PathVariable int boardId,
		@RequestBody Board board) {

		board.setBoardId(boardId);
		board.setMemberId(loginUser.getMemberId());
		log.info("setBoard 호출 - payload: {}", board);

		boardService.setBoard(board);
		return ResponseEntity.ok("게시글 수정 성공");
	}

	@PostMapping("/bookmark/{boardId}")
	public ResponseEntity<Boolean> toggleBookmark(
		@AuthenticationPrincipal AuthenticatedUser loginUser,
		@PathVariable("boardId") int boardId
	) {
		if (loginUser == null) {
			return ResponseEntity.status(401).build();
		}

		Board board = Board.builder()
			.boardId(boardId)
			.memberId(loginUser.getMemberId())  // ← 반드시 추가
			.build();

		boolean nowBookmarked = boardService.toggleBookmark(board);
		return ResponseEntity.ok(nowBookmarked);
	}
}
