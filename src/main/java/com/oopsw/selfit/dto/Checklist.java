package com.oopsw.selfit.dto;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Checklist {
	private int memberId;
	private int checklistId;
	private int checkId;
	private String checkDate;
	private String checkContent;
	private int isCheck;
}
