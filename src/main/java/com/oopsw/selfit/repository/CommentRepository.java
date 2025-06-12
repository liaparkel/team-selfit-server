package com.oopsw.selfit.repository;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import com.oopsw.selfit.domain.Comments;

public interface CommentRepository extends JpaRepository<Comments, Long> {
	//댓글 전체 가져오기
	List<Comments> findByBoardIdOrderByCommentCreatedDateDesc(Long boardId);

	// 페이징 버전
	Page<Comments> findByBoardIdOrderByCommentCreatedDateDesc(Long boardId, Pageable pageable);

}