package com.oopsw.selfit.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.*;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class ExerciseApiWrapper {
	private int currentCount;
	private List<ExerciseApi> data;
	private int matchCount;
	private int page;
	private int perPage;
	private int totalCount;
}
