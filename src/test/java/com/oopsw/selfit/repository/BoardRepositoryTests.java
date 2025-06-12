package com.oopsw.selfit.repository;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import com.oopsw.selfit.dto.Board;
import com.oopsw.selfit.dto.Bookmark;

@Transactional
@SpringBootTest
public class BoardRepositoryTests {

	@Autowired
	private BoardRepository boardRepository;

	@Test
	public void testGetCategoryYes() {
		// given : 데이터 준비

		// when: 실행
		List<Board> categories = boardRepository.getCategory();

		// then: 실행결과 체크
		assertNotNull(categories);
		assertTrue(categories.size() > 0);
	}

	@Test
	public void testGetBoardYes() {
		// given: 데이터 준비
		Board board = Board.builder().boardId(1).build();

		// when: 실행
		Board result = boardRepository.getBoard(board);

		// then: 실행결과 체크
		assertNotNull(result);
		assertEquals(1, result.getBoardId());
	}

	@Test
	public void testGetBoardInvalid() {
		// given: 데이터 준비
		Board board = Board.builder().boardId(-999).build();

		// when: 실행
		Board result = boardRepository.getBoard(board);

		// then: 실행결과 체크
		assertNull(result);
	}

	@Test
	public void testGetBoardsYes() {
		// given: 데이터 준비
		Map<String, Object> params = new HashMap<>();
		params.put("categoryId", 1);
		params.put("searchKeyword", "");
		params.put("sortOrder", "recent");
		params.put("limit", 10);
		params.put("offset", 0);

		// when: 실행
		List<Board> boards = boardRepository.getBoards(params);

		// then: 실행결과 체크
		assertNotNull(boards);
	}

	@Test
	public void testGetBoardUpdateYes() {
		// given: 데이터 준비
		Board board = Board.builder().boardId(1).build();

		// when: 실행
		Board result = boardRepository.getBoardUpdate(board);

		// then: 실행결과 체크
		assertNotNull(result);
		assertNotNull(result.getBoardTitle());
		assertNotNull(result.getCategoryName());
	}

	@Test
	public void testGetBoardUpdateInvalid() {
		// given: 데이터 준비
		Board board = Board.builder().boardId(-999).build();

		// when: 실행
		Board result = boardRepository.getBoardUpdate(board);

		// then: 실행결과 체크
		assertNull(result);
	}

	@Test
	public void testAddBoardYes() {
		// given: 데이터 준비
		Board board = Board.builder()
			.boardTitle("테스트 제목")
			.boardContent("테스트 내용")
			.viewCount(0)
			.createdDate(null)
			.boardImg("test.jpg")
			.categoryId(1)
			.memberId(1)
			.build();

		// when: 실행
		int result = boardRepository.addBoard(board);

		// then: 실행결과 체크
		assertEquals(1, result);
	}

	@Test
	public void testAddBookmarkYes() {
		// given: 데이터 준비
		Board board = Board.builder()
			.boardId(1)
			.memberId(1)
			.build();

		// when: 실행
		int inserted = boardRepository.addBookmark(board);

		// then: 실행결과 체크
		assertEquals(1, inserted);
	}

	@Test
	public void testGetBookmarkCountYes() {
		// given: 데이터 준비
		Board board = Board.builder()
			.memberId(1)
			.boardId(1)
			.build();

		// when: 실행
		int count = boardRepository.getBookmarkCount(board);

		// then: 실행결과 체크
		assertTrue(count >= 0); // 실제 DB에 따라 0 또는 1 이상
	}

	@Test
	public void testGetBookmarkCountInvalid() {
		// given: 데이터 준비 (존재하지 않는 조합)
		Board board = Board.builder()
			.memberId(-999)  // 없는 유저
			.boardId(-999)   // 없는 게시글
			.build();

		// when: 실행
		int count = boardRepository.getBookmarkCount(board);

		// then: 실행결과 체크
		assertEquals(0, count); // 존재하지 않으면 0이어야 정상
	}

	@Test
	public void testRemoveBookmarkYes() {
		// given: 데이터 준비
		Board board = Board.builder()
			.memberId(1)
			.boardId(1)
			.build();

		// when: 실행
		int deleted = boardRepository.removeBookmark(board);

		// then: 실행결과 체크
		assertTrue(deleted == 0 || deleted == 1); // 이미 없을 수도 있기 때문에 유연하게 검사
	}

	@Test
	public void testRemoveBookmarkInvalid() {
		// given: 데이터 준비 (존재하지 않는 조합)
		Board board = Board.builder()
			.memberId(-999)
			.boardId(-999)
			.build();

		// when: 실행
		int deleted = boardRepository.removeBookmark(board);

		// then: 실행결과 체크
		assertEquals(0, deleted); // 삭제할 게 없으니까 0
	}

	@Test
	public void testSetBoardYes() {
		// given: 데이터 준비
		Board board = Board.builder()
			.boardId(1)
			.boardTitle("수정된 제목")
			.boardContent("수정된 내용")
			.boardImg("updated.jpg")
			.categoryId(1)
			.build();

		// when: 실행
		int result = boardRepository.setBoard(board);

		// then: 실행결과 체크
		assertEquals(1, result);
	}

	@Test
	public void testSetBoardInvalidId() {
		// given: 데이터 준비
		Board board = Board.builder()
			.boardId(-999)
			.boardTitle("수정 실패")
			.boardContent("내용")
			.boardImg("img.jpg")
			.categoryId(1)
			.build();

		// when: 실행
		int result = boardRepository.setBoard(board);

		// then: 실행결과 체크
		assertEquals(0, result);
	}

	@Test
	public void testRemoveBoardYes() {
		// given: 데이터 준비
		Board board = Board.builder().boardId(1).build();

		// when: 실행
		int result = boardRepository.removeBoard(board);

		// then: 실행결과 체크
		assertEquals(1, result);
	}

	@Test
	public void testRemoveBoardInvalid() {
		// given: 데이터 준비
		Board board = Board.builder().boardId(-999).build();

		// when: 실행
		int result = boardRepository.removeBoard(board);

		// then: 실행결과 체크
		assertEquals(0, result);
	}

	@Test
	public void testGetBookmarksPagedYes() {
		//given

		//when
		List<Bookmark> list = boardRepository.getBookmarks(1, 5, 0);

		//then
		assertTrue(list.size() <= 5);
	}

	//페이지당 n개일 때 n개 이하가 잘 나오는지 확인
	@Test
	public void testGetBookmarksPagedExactLimit() {
		//given
		int limit = 2;
		int offset = 0;

		//when
		List<Bookmark> list = boardRepository.getBookmarks(1, limit, offset);

		//then
		assertNotNull(list);
		assertTrue(list.size() <= limit);
	}

	//offset이 너무 커서 결과 없는지 확인
	@Test
	public void testGetBookmarksPagedOffsetOver() {
		//given
		int offset = 9999;

		//when
		List<Bookmark> list = boardRepository.getBookmarks(1, 5, offset);

		//then
		assertNotNull(list);
		assertEquals(0, list.size()); // offset이 너무 커서 결과 없음
	}

	@Test
	public void testGetBookmarksPagedInvalidMemberId() {
		//given

		//when
		List<Bookmark> list = boardRepository.getBookmarks(-1, 5, 0);

		//then
		assertTrue(list.isEmpty());
	}
}
