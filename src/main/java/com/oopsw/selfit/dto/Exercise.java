package com.oopsw.selfit.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Exercise {
	private int memberId;
	private int exerciseNoteId;
	private int exerciseInfoId;
	// private int exerciseId;
	private String exerciseName;
	private int exerciseMin;
	private int exerciseKcal;
	private float met;
	private String exerciseDate;
	private int exerciseSum; //소모 칼로리 합
}
