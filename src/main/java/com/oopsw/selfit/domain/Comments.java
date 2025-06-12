package com.oopsw.selfit.domain;

import java.time.LocalDateTime;

import org.hibernate.annotations.CreationTimestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "COMMENTS") // 새 테이블명 명시
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Comments {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "COMMENT_ID")
	private int commentId;

	@Column(name = "COMMENT_CONTENT", nullable = false)
	private String commentContent;

	@CreationTimestamp
	@Column(name = "COMMENT_CREATED_DATE", nullable = false, updatable = false)
	private LocalDateTime commentCreatedDate;

	@Column(name = "BOARD_ID", nullable = false)
	private Long boardId;

	@Column(name = "MEMBER_ID", nullable = false)
	private int memberId;

}
