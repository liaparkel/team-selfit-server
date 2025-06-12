package com.oopsw.selfit.service;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.oopsw.selfit.dto.ExerciseApi;
import com.oopsw.selfit.repository.ExerciseApiRepository;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class ExerciseApiService {
	private final ExerciseApiRepository exerciseApiRepository;

	public Mono<List<ExerciseApi>> getExercises(int pageNo, int numOfRows) {
		if (pageNo < 1 || numOfRows < 1) {
			return Mono.error(new IllegalArgumentException("pageNo와 numOfRows는 1 이상이어야 합니다."));
		}
		return exerciseApiRepository.fetchExerciseData(pageNo, numOfRows);
	}

	public Mono<List<ExerciseApi>> getExercisesByNameLike(String keyword, int pageNo, int numOfRows) {
		if (keyword == null || keyword.isBlank()) {
			return Mono.error(new IllegalArgumentException("검색 키워드를 입력해야 합니다."));
		}
		if (pageNo < 1 || numOfRows < 1) {
			return Mono.error(new IllegalArgumentException("pageNo와 numOfRows는 1 이상이어야 합니다."));
		}

		return exerciseApiRepository.fetchExerciseData(pageNo, numOfRows)
			.map(list ->
				// null-safe 필터링
				(list != null ? list.stream()
					.filter(item -> {
						String name = item.getExerciseName();
						return name != null && name.contains(keyword);
					})
					.collect(Collectors.toList())
					: Collections.emptyList())
			);
	}
}

