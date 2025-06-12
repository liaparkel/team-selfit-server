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
@Table(name = "EXERCISE_INFOS") //테이블명 명시
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ExerciseInfos {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "EXERCISE_INFO_ID")
	private int exerciseInfoId;

	@Column(name = "EXERCISE_NAME", nullable = false)
	private String exerciseName;

	@Column(name = "EXERCISE_MIN", nullable = false)
	private int exerciseMin;

	@Column(name = "EXERCISE_KCAL", nullable = false)
	private float exerciseKcal;

	@Column(name = "MET", nullable = false)
	private float met;

	@Column(name = "EXERCISE_NOTE_ID", nullable = false)
	private int exerciseNoteId;
}
