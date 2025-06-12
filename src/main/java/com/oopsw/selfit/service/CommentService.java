package com.oopsw.selfit.service;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import com.oopsw.selfit.domain.Comments;
import com.oopsw.selfit.dto.Board;
import com.oopsw.selfit.dto.Comment;
import com.oopsw.selfit.dto.Member;
import com.oopsw.selfit.repository.BoardRepository;
import com.oopsw.selfit.repository.CommentRepository;
import com.oopsw.selfit.repository.CommentsRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CommentService {
	private final CommentRepository commentRepository;
	private final BoardRepository boardRepository;
	private final CommentsRepository commentsRepository;

	public List<Comment> getComments(int boardId, int page) {
		int pageSize = 5;
		Pageable pageable = PageRequest.of(page - 1, pageSize);

		// 엔티티 가져오기
		Page<Comments> commentEntities = commentRepository
			.findByBoardIdOrderByCommentCreatedDateDesc((long)boardId, pageable);

		long totalComments = commentEntities.getTotalElements(); // 전체 댓글 개수

		if (commentEntities.isEmpty()) {
			return Collections.emptyList();
		}

		return commentEntities.stream()
			.map(entity -> {
				Member memberInfo = commentsRepository.getMemberImg(
					Member.builder().memberId(entity.getMemberId()).build()
				);
				return Comment.builder()
					.commentId(entity.getCommentId())
					.commentContent(entity.getCommentContent())
					.commentDate(entity.getCommentCreatedDate())
					.nickName(memberInfo.getNickname())
					.profileImg(memberInfo.getProfileImg())
					.totalCount((int)totalComments)
					.build();
			})
			.collect(Collectors.toList());
	}

	public boolean addComment(Comment comment) {
		// 게시글 존재 여부 확인
		Board board = Board.builder()
			.boardId(comment.getBoardId())
			.build();

		if (boardRepository.getBoard(board) == null) {
			throw new IllegalArgumentException("존재하지 않는 게시글입니다.");
		}
		// 댓글 저장
		Comments entity = Comments.builder()
			.commentContent(comment.getCommentContent())
			.boardId((long)comment.getBoardId())
			.memberId(comment.getMemberId())
			.build();

		commentRepository.save(entity);
		return true;
	}
}
