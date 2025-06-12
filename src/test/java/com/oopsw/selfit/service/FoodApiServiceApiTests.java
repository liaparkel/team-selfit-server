package com.oopsw.selfit.service;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.oopsw.selfit.dto.FoodApi;
import com.oopsw.selfit.repository.FoodApiRepository;

import reactor.core.publisher.Mono;

@SpringBootTest
public class FoodApiServiceApiTests {
	@Autowired
	private FoodApiService foodApiService;

	@Test
	public void testGetFoodByNameLike() {
		// given
		String keyword = "베이컨";
		int pageNo = 1;
		int numOfRows = 100;

		// when
		Mono<List<FoodApi>> monoResult = foodApiService.getFoodByNameLike(keyword, pageNo, numOfRows);
		List<FoodApi> resultList = monoResult.block();  // 동기 호출

		// then
		assertNotNull(resultList, "결과 리스트는 null이어서는 안 된다");
		assertFalse(resultList.isEmpty(), "결과 리스트는 비어 있으면 안 된다");

		// 모든 항목의 foodNm에 keyword가 포함되어야 한다
		List<String> failing = resultList.stream()
			.map(FoodApi::getFoodNm)
			.filter(name -> name == null || !name.contains(keyword))
			.collect(Collectors.toList());
		assertTrue(failing.isEmpty(),
			"모든 결과의 foodNm에 '" + keyword + "'이(가) 포함되어야 합니다. 잘못된 항목: " + failing);

		// (선택) 콘솔 출력
		System.out.println("---- 부분 검색 결과 (keyword=" + keyword + ") ----");
		resultList.forEach(item ->
			System.out.printf("  ▶ code=%s, name=%s, kcal=%s, size=%s%n",
				item.getFoodCd(), item.getFoodNm(), item.getEnerc(), item.getFoodSize())
		);

	}
}
