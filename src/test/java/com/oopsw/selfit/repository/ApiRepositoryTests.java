package com.oopsw.selfit.repository;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.oopsw.selfit.dto.ExerciseApi;
import com.oopsw.selfit.dto.FoodApi;

import reactor.core.publisher.Mono;

@SpringBootTest
public class ApiRepositoryTests {

	@Autowired
	private ExerciseApiRepository exerciseApiRepository;
	@Autowired
	private FoodApiRepository foodApiRepository;

	@Test
	public void testGetExerciseApi() {
		// given
		int page = 1;
		int size = 10;

		// when
		Mono<List<ExerciseApi>> monoResult = exerciseApiRepository.fetchExerciseData(page, size);
		List<ExerciseApi> resultList = monoResult.block();  // 동기 호출

		// then
		assertNotNull(resultList, "운동 API 결과 리스트는 null이 아니어야 한다");
		assertFalse(resultList.isEmpty(), "운동 API 결과 리스트는 비어 있지 않아야 한다");

		System.out.println(resultList);

	}

	@Test
	public void testGetFoodApi() {
		// given
		int page = 1;
		int size = 10;

		// when
		Mono<List<FoodApi>> monoResult = foodApiRepository.fetchFoodData(page, size);
		List<FoodApi> resultList = monoResult.block();  // 동기 호출

		// then
		assertNotNull(resultList, "운동 API 결과 리스트는 null이 아니어야 한다");
		assertFalse(resultList.isEmpty(), "운동 API 결과 리스트는 비어 있지 않아야 한다");

		System.out.println(resultList);

	}

}




