package com.oopsw.selfit.repository;

import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import org.springframework.web.reactive.function.client.WebClient;

import com.oopsw.selfit.dto.ExerciseApi;
import com.oopsw.selfit.dto.ExerciseApiWrapper;

import reactor.core.publisher.Mono;

@Repository
public class ExerciseApiRepository {
	private final WebClient exerciseApiClient;
	@Value("${exercise.key}")
	private String apiKey;

	public ExerciseApiRepository(WebClient exerciseApiClient) {
		this.exerciseApiClient = exerciseApiClient;
	}

	public Mono<List<ExerciseApi>> fetchExerciseData(int page, int size) {
		return exerciseApiClient.get()
			.uri(b -> b
				.queryParam("serviceKey", apiKey)
				.queryParam("page", page)
				.queryParam("perPage", size)
				.queryParam("type", "json")
				.build()
			)
			.retrieve()
			.bodyToMono(ExerciseApiWrapper.class)
			.map(ExerciseApiWrapper::getData);
	}

	public Mono<List<ExerciseApi>> fetchExerciseDataByName(String exerciseName, int page, int size) {
		return exerciseApiClient.get()
			.uri(b -> {
				// exerciseName 파라미터를 추가로 붙인다
				return b
					.queryParam("serviceKey", apiKey)
					.queryParam("page", page)
					.queryParam("perPage", size)
					.queryParam("type", "json")
					.queryParam("cond[운동명::Like]", exerciseName)  // 운동명에 따른 검색
					.build();
			})
			.retrieve()
			.bodyToMono(ExerciseApiWrapper.class)
			.map(ExerciseApiWrapper::getData);
	}
}

