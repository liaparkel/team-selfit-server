package com.oopsw.selfit.service;

import static org.junit.jupiter.api.Assertions.*;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.oopsw.selfit.dto.ExerciseApi;

import reactor.core.publisher.Mono;

@SpringBootTest
public class ExerciseApiServiceTests {
	@Autowired
	private ExerciseApiService exerciseApiService;

	@Test
	void testGetExercisesByNameLike() {
		// given
		String keyword = "요가";
		int page = 1;
		int size = 50;

		// when
		Mono<List<ExerciseApi>> monoResult = exerciseApiService.getExercisesByNameLike(keyword, page, size);
		List<ExerciseApi> exerciseList = monoResult.block();

		// then
		assertNotNull(exerciseList, "리턴된 리스트가 null이어서는 안 됩니다.");

		// 검색 결과가 있으면, 모두 이름에 “스쿼트”가 포함되어 있어야 합니다.
		if (!exerciseList.isEmpty()) {
			List<String> failing = exerciseList.stream()
				.map(ExerciseApi::getExerciseName)
				.filter(name -> name == null || !name.contains(keyword))
				.collect(Collectors.toList());
			assertTrue(failing.isEmpty(),
				"모든 결과의 운동명에는 '" + keyword + "'이 포함되어야 합니다. 잘못된 항목: " + failing);
		}

		// (선택) 콘솔에 찍어보기
		System.out.println("---- LIKE 검색 결과 (키워드=" + keyword + ") ----");
		exerciseList.forEach(item ->
			System.out.printf("  ▶ name=%s, met=%.1f%n",
				item.getExerciseName(), item.getMet())
		);
	}
}
