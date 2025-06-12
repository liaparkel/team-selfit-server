package com.oopsw.selfit.service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Service;

import com.oopsw.selfit.dto.Board;
import com.oopsw.selfit.repository.BoardRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class BoardService {
	private final BoardRepository boardRepository;

	private void validateBoardRequiredFields(Board board) {
		if (board.getBoardTitle() == null || board.getBoardTitle().isBlank()) {
			throw new IllegalArgumentException("제목은 필수입니다.");
		}
		if (board.getBoardContent() == null || board.getBoardContent().isBlank()) {
			throw new IllegalArgumentException("내용은 필수입니다.");
		}
		if (board.getCategoryId() <= 0) {
			throw new IllegalArgumentException("카테고리를 선택해주세요.");
		}
	}

	public List<Board> getCategory() {
		return boardRepository.getCategory();
	}

	public Board getBoard(Board board) {
		boardRepository.setViewCount(board.getBoardId());
		return boardRepository.getBoard(board);
	}

	public List<Board> getBoards(int categoryId, String keyword, String sortOrder, int page) {
		int pageSize = 10;
		int offset = (page - 1) * pageSize;

		Map<String, Object> map = new HashMap<>();
		map.put("categoryId", categoryId);
		map.put("searchKeyword", keyword == null ? "" : keyword);
		map.put("sortOrder", sortOrder == null ? "recent" : sortOrder);
		map.put("limit", pageSize);
		map.put("offset", offset);

		List<Board> boards = boardRepository.getBoards(map);

		return boards;
	}

	public Board getBoardUpdate(Board board) {
		return boardRepository.getBoardUpdate(board);
	}

	public boolean addBoard(Board board) {
		validateBoardRequiredFields(board);

		// 2. 저장
		int result = boardRepository.addBoard(board);
		if (result <= 0) {
			throw new IllegalStateException("게시글 등록에 실패했습니다.");
		}
		return true;
	}

	public boolean toggleBookmark(Board board) {
		if (board.getBoardId() <= 0 || board.getMemberId() <= 0) {
			throw new IllegalArgumentException("boardId와 memberId는 0보다 커야 합니다.");
		}
		int count = boardRepository.getBookmarkCount(board);

		if (count == 0) {
			boardRepository.addBookmark(board);
			return true;
		} else {
			boardRepository.removeBookmark(board);
			return false;
		}
	}

	public boolean setBoard(Board board) {
		// 1) 공통 유효성 검증 호출
		validateBoardRequiredFields(board);

		// 2) 기존 게시글 조회
		Board existing = boardRepository.getBoard(
			Board.builder().boardId(board.getBoardId()).build()
		);
		if (existing == null) {
			throw new IllegalStateException("존재하지 않는 게시글입니다.");
		}
		// 작성자 권한 확인
		if (existing.getMemberId() != board.getMemberId()) {
			throw new IllegalStateException("수정 권한이 없습니다.");
		}

		// 3) 실제 UPDATE 수행
		int rowsAffected = boardRepository.setBoard(board);
		if (rowsAffected <= 0) {
			throw new IllegalStateException("게시글 수정에 실패했습니다.");
		}
		return true;
	}

	public boolean removeBoard(Board board) {
		int rowsAffected = boardRepository.removeBoard(board);
		if (rowsAffected <= 0) {
			// 실제로 삭제가 되지 않았을 경우(권한 없음, 존재하지 않는 글 등)
			throw new IllegalStateException("게시글 삭제에 실패했습니다.");
		}
		return true;
	}
}
