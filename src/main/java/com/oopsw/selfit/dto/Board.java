package com.oopsw.selfit.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Board {
	private int memberId;
	private int boardId;
	private int categoryId;
	private String categoryName;
	private String boardTitle;
	private String boardContent;
	private String boardImg;
	private String createdDate;
	private String nickName;
	private String memberImg;
	private int viewCount;
	private int bookmarkCount;
	private int commentCount;
	private int totalCount;
}