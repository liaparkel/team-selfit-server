package com.oopsw.selfit.repository;

import java.util.List;
import java.util.Map;

import org.apache.ibatis.annotations.Mapper;

import com.oopsw.selfit.dto.Board;
import com.oopsw.selfit.dto.Bookmark;

@Mapper
public interface BoardRepository {
	List<Board> getCategory();

	Board getBoard(Board board);

	List<Board> getBoards(Map<String, Object> map);

	Board getBoardUpdate(Board board);

	int addBoard(Board board);

	int addBookmark(Board board);

	int removeBookmark(Board board);

	int getBookmarkCount(Board board);

	List<Bookmark> getBookmarks(int memberId, int limit, int offset);

	int setBoard(Board board);

	int removeBoard(Board board);

	int setViewCount(int boardId);
}
