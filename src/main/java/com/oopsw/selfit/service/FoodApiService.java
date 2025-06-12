package com.oopsw.selfit.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.oopsw.selfit.dto.FoodApi;
import com.oopsw.selfit.repository.FoodApiRepository;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class FoodApiService {
	private final FoodApiRepository foodApiRepository;

	public Mono<List<FoodApi>> getFoods(int pageNo, int numOfRows) {
		// 1) 파라미터 유효성 검사
		if (pageNo < 1 || numOfRows < 1) {
			return Mono.error(new IllegalArgumentException("pageNo, numOfRows는 1 이상이어야 합니다."));
		}

		// 2) 외부 API 호출
		return foodApiRepository.fetchFoodData(pageNo, numOfRows);
	}

	public Mono<List<FoodApi>> getFoodByNameLike(String keyword, int pageNo, int numOfRows) {
		if (keyword == null || keyword.isBlank()) {
			return Mono.error(new IllegalArgumentException("검색 키워드를 입력해야 합니다."));
		}
		if (pageNo < 1 || numOfRows < 1) {
			return Mono.error(new IllegalArgumentException("pageNo와 numOfRows는 1 이상이어야 합니다."));
		}

		return foodApiRepository.fetchFoodData(pageNo, numOfRows)
			.map(list ->
				// Java 스트림을 이용해 'foodNm'에 keyword 포함된 항목만 필터
				list.stream()
					.filter(item -> {
						// null 검사 추가
						String name = item.getFoodNm();
						return name != null && name.contains(keyword);
					})
					.collect(Collectors.toList())
			);
	}

}

