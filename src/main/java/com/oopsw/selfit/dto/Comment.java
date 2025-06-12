package com.oopsw.selfit.dto;

import java.time.LocalDateTime;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Comment {
	private int memberId;
	private int boardId;
	private int commentId;
	private LocalDateTime commentDate;
	private String commentContent;
	private String nickName;
	private String profileImg;
	private int totalCount;
}