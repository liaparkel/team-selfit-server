package com.oopsw.selfit.repository;

import java.util.List;
import java.util.Map;

import org.apache.ibatis.annotations.Mapper;

import com.oopsw.selfit.dto.Comment;
import com.oopsw.selfit.dto.Member;

@Mapper
public interface CommentsRepository {
	List<Comment> getComments(Map<String, Object> map);

	int addComment(Comment comment);

	Member getMemberImg(Member member);
}
