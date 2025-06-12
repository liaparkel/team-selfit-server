package com.oopsw.selfit.domain;

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
@Table(name = "CHECK_ITEMS") // 새 테이블명 명시
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CheckItem {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "CHECK_ID")
	private Long checkId;

	@Column(name = "CHECK_CONTENT", nullable = false)
	private String checkContent;

	@Column(name = "IS_CHECK", nullable = false)
	private Boolean isCheck;

	@Column(name = "CHECKLIST_ID", nullable = false)
	private Long checklistId;
}
