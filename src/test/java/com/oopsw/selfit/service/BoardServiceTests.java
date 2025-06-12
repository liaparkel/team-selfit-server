package com.oopsw.selfit.service;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import com.oopsw.selfit.dto.Board;

@Transactional
@SpringBootTest
public class BoardServiceTests {

	@Autowired
	private BoardService boardService;

	@Test
	public void testGetCategoryYes() {
		// given : 데이터 준비

		// when : 실행
		List<Board> categories = boardService.getCategory();

		// then : 실행결과 체크
		assertNotNull(categories);
		assertTrue(categories.size() > 0);
	}

	@Test
	public void testGetBoardYes() {
		// given : 데이터 준비
		Board board = Board.builder()
			.boardId(1)
			.build();
		// when : 실행
		Board result = boardService.getBoard(board);
		// then : 실행결과 체크
		assertNotNull(result);
		assertEquals(1, result.getBoardId());
	}

	@Test
	public void testGetBoardInvalid() {
		// given : 데이터 준비
		Board board = Board.builder().boardId(-999).build();

		// when : 실행
		Board result = boardService.getBoard(board);

		// then : 실행결과 체크
		assertNull(result);
	}

	@Test
	public void testGetBoardsYes() {
		// given : 데이터 준비
		int categoryId = 1;
		String keyword = "";
		String sortOrder = "recent";
		int page = 1;
		// when : 실행
		List<Board> boards = boardService.getBoards(categoryId, keyword, sortOrder, page);
		// then : 실행결과 체크
		assertNotNull(boards);
		assertFalse(boards.isEmpty());
	}

	@Test
	public void testGetBoardUpdateYes() {
		// given : 데이터 준비
		Board board = Board.builder()
			.boardId(1)
			.build();

		// when : 실행
		Board result = boardService.getBoardUpdate(board);

		// then : 실행결과 체크
		assertNotNull(result);
		assertNotNull(result.getBoardTitle());
	}

	@Test
	public void testGetBoardUpdateInvalid() {
		// given : 데이터 준비
		Board board = Board.builder().boardId(-999).build();

		// when : 실행
		Board result = boardService.getBoardUpdate(board);

		// then : 실행결과 체크
		assertNull(result);
	}

	@Test
	public void testAddBoardYes() {
		// given : 데이터 준비
		Board board = Board.builder()
			.boardTitle("테스트 제목")
			.boardContent("테스트 내용")
			.viewCount(0)
			.createdDate(null)
			.boardImg("test.jpg")
			.categoryId(1)
			.memberId(1)
			.build();
		// when : 실행
		boolean result = boardService.addBoard(board);

		// then : 실행결과 체크
		assertTrue(result);
	}

	@Test
	public void testToggleBookmarkYes() {
		// given : 데이터 준비
		Board board = Board.builder()
			.boardId(1)
			.memberId(2)
			.build();

		// when 1 : 이미 존재하므로 북마크 제거 (else 분기)
		boolean result1 = boardService.toggleBookmark(board);

		// when 2 : 다시 추가 (if 분기)
		boolean result2 = boardService.toggleBookmark(board);

		// then : 실행결과 체크
		assertFalse(result1);
		assertTrue(result2);
	}

	@Test
	public void testSetBoardYes() {
		// given : 데이터 준비
		Board board = Board.builder()
			.boardId(1)
			.boardTitle("수정된 제목")
			.boardContent("수정된 내용")
			.boardImg("updated.jpg")
			.categoryId(1)
			.build();

		// when : 실행
		boolean result = boardService.setBoard(board);

		// then : 실행결과 체크
		assertTrue(result);
	}

	@Test
	public void testSetBoardInvalidId() {
		// given : 데이터 준비
		Board board = Board.builder()
			.boardId(-999)
			.boardTitle("수정 실패")
			.boardContent("내용")
			.boardImg("img.jpg")
			.categoryId(1)
			.build();

		// when : 실행
		boolean result = boardService.setBoard(board);

		// then : 실행결과 체크
		assertFalse(result);
	}

	@Test
	public void testRemoveBoardYes() {
		// given : 데이터 준비
		Board board = Board.builder().boardId(1).build();

		// when : 실행
		boolean result = boardService.removeBoard(board);

		// then : 실행결과 체크
		assertTrue(result);
	}

	@Test
	public void testRemoveBoardInvalid() {
		// given : 데이터 준비
		Board board = Board.builder().boardId(-999).build();

		// when : 실행
		boolean result = boardService.removeBoard(board);

		// then : 실행결과 체크
		assertFalse(result);
	}
}
