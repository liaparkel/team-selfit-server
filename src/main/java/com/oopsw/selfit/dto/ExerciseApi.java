package com.oopsw.selfit.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class ExerciseApi {
	@JsonProperty("단위체중당에너지소비량")
	private float met;

	@JsonProperty("운동명")
	private String exerciseName;
}
