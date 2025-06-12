package com.oopsw.selfit.repository;

import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import org.springframework.web.reactive.function.client.WebClient;

import com.oopsw.selfit.dto.FoodApi;
import com.oopsw.selfit.dto.FoodApiWrapper;

import reactor.core.publisher.Mono;

@Repository
public class FoodApiRepository {
	private final WebClient foodApiClient;
	@Value("${food.key}")
	private String apiKey;

	public FoodApiRepository(WebClient foodApiClient) {
		this.foodApiClient = foodApiClient;
	}

	/** 외부 API에서 하루치 데이터를 가져와 List<FoodApi>로 반환 */
	public Mono<List<FoodApi>> fetchFoodData(int pageNo, int numOfRows) {
		return foodApiClient.get()
			.uri(uri -> uri
				.queryParam("serviceKey", apiKey)
				.queryParam("pageNo", pageNo)
				.queryParam("numOfRows", numOfRows)
				.queryParam("type", "json")
				.build()
			)
			.retrieve()
			.bodyToMono(FoodApiWrapper.class)
			.map(wrapper -> wrapper.getResponse().getBody().getItems());
	}
}

